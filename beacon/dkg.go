package beacon

import (
	"bytes"
	"fmt"
	"sync"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/types"
)

type dkgState int

const (

	// DKG has two tracks participants and observers. Participants enter all
	// states but observers skip all states except waitForDryRun to obtain DKG output
	dkgStart dkgState = iota
	waitForCoefficientsAndShares
	waitForComplaints
	waitForComplaintAnswers
	waitForQualCoefficients
	waitForQualComplaints
	waitForReconstructionShares
	waitForDryRun
	dkgFinish

	// Number of dkg states with non-zero duration
	dkgStatesWithDuration = int64(dkgFinish) - 1
)

type state struct {
	duration        int64
	onEntry         func()
	onExit          func() bool
	checkTransition func() bool
}

func newState(dur int64, entry func(), exit func() bool, transition func() bool) *state {
	if entry == nil {
		entry = func() {}
	}
	if exit == nil {
		exit = func() bool { return true }
	}
	if transition == nil {
		transition = func() bool { return false }
	}
	ns := &state{
		duration:        dur,
		onEntry:         entry,
		onExit:          exit,
		checkTransition: transition,
	}
	return ns
}

// For now set id equal to validator height but can be a function of other
// dkg parameters as well
func dkgID(validatorHeight int64) int64 {
	return validatorHeight
}

//DistributedKeyGeneration handles dkg messages inside block for one dkg run
type DistributedKeyGeneration struct {
	cmn.BaseService
	mtx sync.RWMutex

	config       *cfg.ConsensusConfig
	chainID      string
	dkgID        int64
	dkgIteration int64

	privValidator   types.PrivValidator
	validatorHeight int64
	valToIndex      map[string]uint // Need to convert crypto.Address into string for key
	validators      types.ValidatorSet
	threshold       uint
	currentAeonEnd  int64
	aeonLength      int64
	stateDuration   int64
	aeonKeys        *aeonDetails

	startHeight   int64
	states        map[dkgState]*state
	currentState  dkgState
	beaconService BeaconSetupService

	dryRunKeys       map[string]DKGOutput
	dryRunSignatures map[string]map[uint]string
	dryRunCount      int64

	sendMsgCallback       func(tx *types.DKGMessage)
	dkgCompletionCallback func(*aeonDetails)
}

// NewDistributedKeyGeneration runs the DKG from messages encoded in transactions
func NewDistributedKeyGeneration(csConfig *cfg.ConsensusConfig, chain string,
	privVal types.PrivValidator, validatorHeight int64, vals types.ValidatorSet, aeonEnd int64, aeonLength int64) *DistributedKeyGeneration {
	dkgThreshold := uint(len(vals.Validators)/2 + 1)
	dkg := &DistributedKeyGeneration{
		config:           csConfig,
		chainID:          chain,
		dkgID:            dkgID(validatorHeight),
		dkgIteration:     0,
		privValidator:    privVal,
		validatorHeight:  validatorHeight,
		valToIndex:       make(map[string]uint),
		validators:       vals,
		currentAeonEnd:   aeonEnd,
		aeonLength:       aeonLength,
		threshold:        dkgThreshold,
		startHeight:      validatorHeight + csConfig.DKGResetDelay,
		states:           make(map[dkgState]*state),
		currentState:     dkgStart,
		dryRunKeys:       make(map[string]DKGOutput),
		dryRunSignatures: make(map[string]map[uint]string),
	}
	dkg.BaseService = *cmn.NewBaseService(nil, "DKG", dkg)

	if dkg.index() < 0 {
		dkg.Logger.Debug("startNewDKG: not in validators", "height", dkg.validatorHeight)
	} else {
		dkg.beaconService = NewBeaconSetupService(uint(len(dkg.validators.Validators)), uint(dkg.threshold), uint(dkg.index()))
	}
	// Set validator address to index
	for index, val := range dkg.validators.Validators {
		dkg.valToIndex[string(val.PubKey.Address())] = uint(index)
	}

	// When computing dkg duration allow buffer for run ahead on entropy generation so that
	// dkg does not complete right at the end of the aeon
	dkgDuration := (aeonLength - dkg.config.EntropyChannelCapacity - 1) / dkg.config.DKGAttemptsInAeon
	// Divide by number of states to get the duration of each state
	dkg.stateDuration = (dkgDuration - dkg.config.DKGResetDelay) / dkgStatesWithDuration
	dkg.setStates()

	return dkg
}

// SetSendMsgCallback sets the function for the DKG to send transactions to the mempool
func (dkg *DistributedKeyGeneration) SetSendMsgCallback(callback func(msg *types.DKGMessage)) {
	dkg.mtx.Lock()
	defer dkg.mtx.Unlock()

	dkg.sendMsgCallback = callback
}

func (dkg *DistributedKeyGeneration) SetDkgCompletionCallback(callback func(aeon *aeonDetails)) {
	dkg.mtx.Lock()
	defer dkg.mtx.Unlock()

	dkg.dkgCompletionCallback = callback
}

func (dkg *DistributedKeyGeneration) setStates() {
	dkg.states[dkgStart] = newState(0, nil, func() bool {
		err := dkg.Start()
		return err == nil
	}, nil)

	if dkg.index() < 0 {
		dkg.states[waitForDryRun] = newState(dkg.stateDuration*dkgStatesWithDuration,
			nil,
			dkg.checkDryRuns,
			dkg.receivedAllDryRuns)
	} else {
		dkg.states[waitForCoefficientsAndShares] = newState(dkg.stateDuration,
			dkg.sendSharesAndCoefficients,
			nil,
			dkg.beaconService.ReceivedAllCoefficientsAndShares)
		dkg.states[waitForComplaints] = newState(dkg.stateDuration,
			dkg.sendComplaints,
			nil,
			dkg.beaconService.ReceivedAllComplaints)
		dkg.states[waitForComplaintAnswers] = newState(dkg.stateDuration,
			dkg.sendComplaintAnswers,
			dkg.buildQual,
			dkg.beaconService.ReceivedAllComplaintAnswers)
		dkg.states[waitForQualCoefficients] = newState(dkg.stateDuration,
			dkg.sendQualCoefficients,
			nil,
			dkg.beaconService.ReceivedAllQualCoefficients)
		dkg.states[waitForQualComplaints] = newState(dkg.stateDuration,
			dkg.sendQualComplaints,
			dkg.beaconService.CheckQualComplaints,
			dkg.beaconService.ReceivedAllQualComplaints)
		dkg.states[waitForReconstructionShares] = newState(dkg.stateDuration,
			dkg.sendReconstructionShares,
			dkg.beaconService.RunReconstruction,
			dkg.beaconService.ReceivedAllReconstructionShares)
		dkg.states[waitForDryRun] = newState(dkg.stateDuration,
			dkg.computeKeys,
			dkg.checkDryRuns,
			dkg.receivedAllDryRuns)
	}
	dkg.states[dkgFinish] = newState(0, dkg.dispatchKeys, nil, nil)
}

//OnReset overrides BaseService
func (dkg *DistributedKeyGeneration) OnReset() error {
	dkg.currentState = dkgStart
	dkg.dkgIteration++
	// Reset start time
	dkg.startHeight = dkg.startHeight + dkg.duration() + dkg.config.DKGResetDelay
	// Reset beaconService
	if dkg.index() >= 0 {
		DeleteBeaconSetupService(dkg.beaconService)
		dkg.beaconService = NewBeaconSetupService(uint(len(dkg.valToIndex)), dkg.threshold, uint(dkg.index()))
	}
	// Reset dry run
	dkg.dryRunKeys = make(map[string]DKGOutput)
	dkg.dryRunSignatures = make(map[string]map[uint]string)
	dkg.dryRunCount = 0
	dkg.aeonKeys = nil
	return nil
}

//OnBlock processes DKG messages from a block
func (dkg *DistributedKeyGeneration) OnBlock(blockHeight int64, trxs []*types.DKGMessage) {
	dkg.mtx.Lock()
	defer dkg.mtx.Unlock()

	if !dkg.IsRunning() {
		dkg.checkTransition(blockHeight)
		return
	}
	dkg.Logger.Debug("OnBlock: received transactions", "height", blockHeight, "numTrx", len(trxs))
	// Process transactions
	for _, trx := range trxs {
		// Decode transaction
		msg := trx

		// Check msg is from validators and verify signature
		index, val := dkg.validators.GetByAddress(msg.FromAddress)
		if err := dkg.checkMsg(msg, index, val); err != nil {
			dkg.Logger.Debug("OnBlock: check msg", "height", blockHeight, "from", msg.FromAddress, "err", err)
			continue
		}

		switch msg.Type {
		case types.DKGShare:
			if dkg.currentState > waitForCoefficientsAndShares {
				continue
			}
			dkg.beaconService.OnShares(msg.Data, uint(index))
		case types.DKGCoefficient:
			if dkg.currentState > waitForCoefficientsAndShares {
				continue
			}
			dkg.beaconService.OnCoefficients(msg.Data, uint(index))
		case types.DKGComplaint:
			if dkg.currentState > waitForComplaints {
				continue
			}
			dkg.beaconService.OnComplaints(msg.Data, uint(index))
		case types.DKGComplaintAnswer:
			if dkg.currentState > waitForComplaintAnswers {
				continue
			}
			dkg.beaconService.OnComplaintAnswers(msg.Data, uint(index))
		case types.DKGQualCoefficient:
			if dkg.currentState > waitForQualCoefficients {
				continue
			}
			dkg.beaconService.OnQualCoefficients(msg.Data, uint(index))
		case types.DKGQualComplaint:
			if dkg.currentState > waitForQualComplaints {
				continue
			}
			dkg.beaconService.OnQualComplaints(msg.Data, uint(index))
		case types.DKGReconstructionShare:
			if dkg.currentState > waitForReconstructionShares {
				continue
			}
			dkg.beaconService.OnReconstructionShares(msg.Data, uint(index))
		case types.DKGDryRun:
			if dkg.currentState > waitForDryRun {
				continue
			}
			dkg.onDryRun(msg.Data, uint(index))
		default:
			dkg.Logger.Error("OnBlock: unknown DKGMessage", "type", msg.Type)
		}
	}

	dkg.checkTransition(blockHeight)
}

func (dkg *DistributedKeyGeneration) index() int {
	index, _ := dkg.validators.GetByAddress(dkg.privValidator.GetPubKey().Address())
	return index
}

func (dkg *DistributedKeyGeneration) checkMsg(msg *types.DKGMessage, index int, val *types.Validator) error {
	if err := msg.ValidateBasic(); err != nil {
		return fmt.Errorf("checkMsg: msg failed ValidateBasic err %v", err)
	}
	if index < 0 {
		return fmt.Errorf("checkMsg: FromAddress not int validator set")
	}
	if msg.DKGID != dkg.dkgID {
		return fmt.Errorf("checkMsg: invalid dkgID %v", msg.DKGID)
	}
	if msg.DKGIteration != dkg.dkgIteration {
		return fmt.Errorf("checkMsg: incorrect dkgIteration %v", msg.DKGIteration)
	}
	if !val.PubKey.VerifyBytes(msg.SignBytes(dkg.chainID), msg.Signature) {
		return fmt.Errorf("checkMsg: failed signature verification")
	}
	if len(msg.ToAddress) != 0 && !bytes.Equal(msg.ToAddress, dkg.privValidator.GetPubKey().Address()) {
		return fmt.Errorf("checkMsg: not ToAddress")
	}
	return nil
}

func (dkg *DistributedKeyGeneration) checkTransition(blockHeight int64) {
	if dkg.currentState == dkgFinish {
		return
	}
	if dkg.stateExpired(blockHeight) || dkg.states[dkg.currentState].checkTransition() {
		dkg.Logger.Debug("checkTransition: state change triggered", "height", blockHeight, "state", dkg.currentState)
		if !dkg.states[dkg.currentState].onExit() {
			dkg.Logger.Error("checkTransition: failed onExit", "height", blockHeight, "state", dkg.currentState, "iteration", dkg.dkgIteration)
			if dkg.currentState == waitForDryRun {
				// If exit function for dry run failed then reset and restart DKG
				dkg.Stop()
				dkg.Reset()
			} else {
				// If exit function failed before dry run then skip intermediate states and
				// wait to see if DKG passes for everyone else
				dkg.currentState = waitForDryRun
				dkg.checkTransition(blockHeight)
			}
			return
		}
		if dkg.currentState == dkgStart && dkg.index() < 0 {
			// If not in validators skip straight to waiting for DKG output
			dkg.currentState = waitForDryRun
			dkg.checkTransition(blockHeight)
			return
		}
		dkg.currentState++
		dkg.states[dkg.currentState].onEntry()
		// Run check transition again in case we can proceed to the next state already
		dkg.checkTransition(blockHeight)
	} else {
		dkg.Logger.Debug("checkTransition: no state change", "height", blockHeight, "state", dkg.currentState, "iteration", dkg.dkgIteration)
	}
}

func (dkg *DistributedKeyGeneration) newDKGMessage(msgType types.DKGMessageType, data string, toAddress crypto.Address) *types.DKGMessage {
	if toAddress == nil {
		toAddress = []byte{}
	}
	newMsg := &types.DKGMessage{
		Type:         msgType,
		DKGID:        dkg.dkgID,
		DKGIteration: dkg.dkgIteration,
		FromAddress:  dkg.privValidator.GetPubKey().Address(),
		ToAddress:    toAddress,
		Data:         data,
	}
	err := dkg.privValidator.SignDKGMessage(dkg.chainID, newMsg)
	if err != nil {
		dkg.Logger.Error(err.Error())
	}
	return newMsg
}

func (dkg *DistributedKeyGeneration) broadcastMsg(msgType types.DKGMessageType, serialisedMsg string, toAddress crypto.Address) {
	msg := dkg.newDKGMessage(msgType, serialisedMsg, toAddress)

	if dkg.sendMsgCallback != nil {
		dkg.sendMsgCallback(msg)
	}
}

func (dkg *DistributedKeyGeneration) sendSharesAndCoefficients() {
	dkg.Logger.Debug("sendSharesAndCoefficients", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGCoefficient, dkg.beaconService.GetCoefficients(), nil)

	for validator, index := range dkg.valToIndex {
		if index != uint(dkg.index()) {
			dkg.broadcastMsg(types.DKGShare, dkg.beaconService.GetShare(index), crypto.Address(validator))
		}
	}
}

func (dkg *DistributedKeyGeneration) sendComplaints() {
	dkg.Logger.Debug("sendComplaints", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGComplaint, dkg.beaconService.GetComplaints(), nil)
}

func (dkg *DistributedKeyGeneration) sendComplaintAnswers() {
	dkg.Logger.Debug("sendComplaintAnswers", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGComplaintAnswer, dkg.beaconService.GetComplaintAnswers(), nil)
}

func (dkg *DistributedKeyGeneration) sendQualCoefficients() {
	dkg.Logger.Debug("sendQualCoefficients", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGQualCoefficient, dkg.beaconService.GetQualCoefficients(), nil)
}

func (dkg *DistributedKeyGeneration) sendQualComplaints() {
	dkg.Logger.Debug("sendQualComplaints", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGQualComplaint, dkg.beaconService.GetQualComplaints(), nil)
}

func (dkg *DistributedKeyGeneration) sendReconstructionShares() {
	dkg.Logger.Debug("sendReconstructionShares", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGReconstructionShare, dkg.beaconService.GetReconstructionShares(), nil)
}

func (dkg *DistributedKeyGeneration) buildQual() bool {
	qualSize := dkg.beaconService.BuildQual()
	if qualSize == 0 {
		dkg.Logger.Info("buildQual: DKG failed", "iteration", dkg.dkgIteration)
		return false
	}
	return true
}

func (dkg *DistributedKeyGeneration) computeKeys() {
	aeonExecUnit := dkg.beaconService.ComputePublicKeys()
	// Create new aeon details - start height either the start
	// of the next aeon or immediately (with some delay)
	nextAeonStart := dkg.currentAeonEnd + 1
	dkgEnd := (dkg.startHeight + dkg.duration())
	if dkgEnd >= nextAeonStart {
		nextAeonStart = dkgEnd + dkg.config.EntropyChannelCapacity + 1
	}
	dkg.aeonKeys = newAeonDetails(dkg.privValidator, dkg.validatorHeight, &dkg.validators, aeonExecUnit,
		nextAeonStart, nextAeonStart+dkg.aeonLength-1)

	dkg.Logger.Debug("sendDryRun", "iteration", dkg.dkgIteration)
	msgToSign := string(cdc.MustMarshalBinaryBare(dkg.aeonKeys.dkgOutput()))
	signature := dkg.aeonKeys.aeonExecUnit.Sign(msgToSign)
	// Broadcast message to notify everyone of completion
	dryRun := DryRunSignature{
		PublicInfo:     *dkg.aeonKeys.dkgOutput(),
		SignatureShare: signature,
	}
	if _, haveKeys := dkg.dryRunKeys[msgToSign]; !haveKeys {
		dkg.dryRunKeys[msgToSign] = *dkg.aeonKeys.dkgOutput()
		dkg.dryRunSignatures[msgToSign] = make(map[uint]string)
	}
	dkg.dryRunSignatures[msgToSign][dkg.valToIndex[string(dkg.privValidator.GetPubKey().Address())]] = signature
	dkg.dryRunCount++

	msg := cdc.MustMarshalBinaryBare(&dryRun)
	dkg.broadcastMsg(types.DKGDryRun, string(msg), nil)
}

func (dkg *DistributedKeyGeneration) dispatchKeys() {
	if dkg.dkgCompletionCallback != nil {
		dkg.dkgCompletionCallback(dkg.aeonKeys)
	}

	// Stop service so we do not process more blocks
	dkg.Stop()
}

func (dkg *DistributedKeyGeneration) stateExpired(blockHeight int64) bool {
	stateEndHeight := dkg.startHeight
	for i := dkgStart; i <= dkg.currentState; i++ {
		state, haveState := dkg.states[i]
		if haveState {
			stateEndHeight += state.duration
		}
	}
	return blockHeight >= stateEndHeight
}

func (dkg *DistributedKeyGeneration) duration() int64 {
	dkgLength := int64(0)
	for _, state := range dkg.states {
		dkgLength += state.duration
	}
	return dkgLength
}

func (dkg *DistributedKeyGeneration) onDryRun(data string, index uint) {
	if dkg.aeonKeys != nil && !dkg.aeonKeys.aeonExecUnit.InQual(index) {
		dkg.Logger.Debug("onDryRun: message from non-qual member")
		return
	}
	dryRun := DryRunSignature{}
	err := cdc.UnmarshalBinaryBare([]byte(data), &dryRun)
	if err != nil {
		dkg.Logger.Error("onDryRun: error decoding msg", "error", err.Error())
		return
	}
	err = dryRun.ValidateBasic()
	if err != nil {
		dkg.Logger.Error("onDryRun: error validating msg", "error", err.Error())
		return
	}
	msgSigned := string(cdc.MustMarshalBinaryBare(&dryRun.PublicInfo))
	if _, haveKeys := dkg.dryRunKeys[msgSigned]; !haveKeys {
		dkg.dryRunKeys[msgSigned] = dryRun.PublicInfo
		dkg.dryRunSignatures[msgSigned] = make(map[uint]string)
	}
	if _, haveSignature := dkg.dryRunSignatures[msgSigned][index]; !haveSignature {
		dkg.dryRunSignatures[msgSigned][index] = dryRun.SignatureShare
		dkg.dryRunCount++
	}
}

func (dkg *DistributedKeyGeneration) receivedAllDryRuns() bool {
	if dkg.index() < 0 {
		return dkg.dryRunCount == int64(len(dkg.validators.Validators))
	}
	// For those who have failed and not set keys wait for everyone except self.
	// Otherwise wait for those in aeon keys
	numValidators := len(dkg.validators.Validators) - 1
	if dkg.aeonKeys != nil {
		numValidators = len(dkg.aeonKeys.validators.Validators)
	}
	return dkg.dryRunCount == int64(numValidators)
}

func (dkg *DistributedKeyGeneration) checkDryRuns() bool {
	encodedOutput := ""
	for encodedKeys, signatures := range dkg.dryRunSignatures {
		if uint(len(signatures)) >= dkg.threshold {
			encodedOutput = encodedKeys
			// Should only be one set of keys which gets threshold signatures
			// if double messages are forbidden
			break
		}
	}

	if len(encodedOutput) == 0 {
		dkg.Logger.Error("checkDryRuns: not enought dry run signatures")
		return false
	}

	// Check signatures with keys that have over threshold signature shares
	signatureShares := NewIntStringMap()
	defer DeleteIntStringMap(signatureShares)
	aeonFile := &AeonDetailsFile{
		PublicInfo: dkg.dryRunKeys[encodedOutput],
	}
	tempKeys := LoadAeonDetails(aeonFile, &dkg.validators, dkg.privValidator)
	for index, signature := range dkg.dryRunSignatures[encodedOutput] {
		if tempKeys.aeonExecUnit.Verify(encodedOutput, signature, index) {
			signatureShares.Set(index, signature)
		}
	}
	if uint(signatureShares.Size()) < dkg.threshold {
		dkg.Logger.Error("checkDryRuns: not enought valid dry run signatures")
		return false
	}
	dryRunGroupSignature := tempKeys.aeonExecUnit.ComputeGroupSignature(signatureShares)
	if !tempKeys.aeonExecUnit.VerifyGroupSignature(encodedOutput, dryRunGroupSignature) {
		dkg.Logger.Error("checkDryRuns: failed to verify dry run group signature")
		return false
	}

	// Reset our aeon keys if they do not match output
	if dkg.aeonKeys == nil || string(cdc.MustMarshalBinaryBare(dkg.aeonKeys.dkgOutput())) != encodedOutput {
		dkg.aeonKeys = tempKeys
	}
	return true
}

//-------------------------------------------------------------------------------------------

// DryRunSignature is struct publishing public dkg output with group signature
type DryRunSignature struct {
	PublicInfo     DKGOutput `json:"public_info"`
	SignatureShare string    `json:"group_signature"`
}

// ValidateBasic for basic validity checking of aeon file
func (dryRun *DryRunSignature) ValidateBasic() error {
	err := dryRun.PublicInfo.ValidateBasic()
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	if len(dryRun.SignatureShare) == 0 || len(dryRun.SignatureShare) > types.MaxThresholdSignatureSize {
		return fmt.Errorf("Invalid signature share size %v", len(dryRun.SignatureShare))
	}
	return nil
}
