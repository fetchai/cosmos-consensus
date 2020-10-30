package beacon

import (
	"bytes"
	"io/ioutil"
	"fmt"
	"github.com/tendermint/tendermint/libs/tempfile"
	"runtime"
	"sync"
	"os"
	"errors"

	"github.com/flynn/noise"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto"
	bits "github.com/tendermint/tendermint/libs/bits"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/mcl_cpp"
	tmnoise "github.com/tendermint/tendermint/noise"
	"github.com/tendermint/tendermint/types"
)

type dkgState int

const (

	// DKG has two tracks participants and observers. Participants enter all
	// states but observers skip all states except waitForDryRun to obtain DKG output
	dkgStart dkgState = iota
	waitForEncryptionKeys
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
	// Multplier for increasing state duration on next dkg iteration
	dkgIterationDurationMultiplier = float64(0.5)
	maxDKGStateDuration            = int64(400)
	// Offset required to give app sufficient time to be notified of next aeon
	// start for triggering validator changeovers
	keylessOffset = int64(2)
)

type state struct {
	durationMultiplier int64
	onEntry            func()
	onExit             func() bool
	checkTransition    func() bool
}

func newState(durMultiplier int64, entry func(), exit func() bool, transition func() bool) *state {
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
		durationMultiplier: durMultiplier,
		onEntry:            entry,
		onExit:             exit,
		checkTransition:    transition,
	}
	return ns
}

// DistributedKeyGeneration handles dkg messages inside block for dkg runs, until a successful dkg is completed.
// Empty keys are dispatched for the duration of the dkg [dkgStart, dkgEnd + 1] to allow trivial entropy generation
// if no current keys exist.
type DistributedKeyGeneration struct {
	service.BaseService
	mtx sync.RWMutex

	config       *cfg.BeaconConfig
	baseConfig   *cfg.BaseConfig

	chainID      string
	dkgID        int64
	dkgIteration int64

	privValidator   types.PrivValidator
	validatorHeight int64
	valToIndex      map[string]uint // Need to convert crypto.Address into string for key
	validators      types.ValidatorSet
	threshold       uint
	currentAeonEnd  int64
	entropyParams   types.EntropyParams
	stateDuration   int64
	aeonKeys        *aeonDetails
	onFailState     func(int64)
	enableRecovery  bool

	startHeight   int64
	states        map[dkgState]*state
	currentState  dkgState
	beaconService mcl_cpp.BeaconSetupService

	earlySecretShares map[uint]string
	dryRunKeys        map[string]DKGOutput
	dryRunSignatures  map[string]map[string]string
	dryRunCount       *bits.BitArray

	sendMsgCallback       func(tx *types.DKGMessage)
	dkgCompletionCallback func(*aeonDetails)

	encryptionKey        noise.DHKey
	encryptionPublicKeys map[uint][]byte

	metrics              *Metrics
	slotProtocolEnforcer *SlotProtocolEnforcer

	evidenceHandler func(*types.DKGEvidence)
}


// NewDistributedKeyGeneration runs the DKG from messages encoded in transactions
func NewDistributedKeyGeneration(beaconConfig *cfg.BeaconConfig, baseConfig *cfg.BaseConfig, chain string,
	privVal types.PrivValidator, dhKey noise.DHKey, validatorHeight int64, dkgID int64, vals types.ValidatorSet,
	aeonEnd int64, entropyParams types.EntropyParams, slotProtocolEnforcer *SlotProtocolEnforcer) *DistributedKeyGeneration {
	dkgThreshold := uint(len(vals.Validators)/2 + 1)
	dkg := &DistributedKeyGeneration{
		config:               beaconConfig,
		baseConfig:           baseConfig,
		chainID:              chain,
		dkgID:                dkgID,
		dkgIteration:         0,
		privValidator:        privVal,
		validatorHeight:      validatorHeight,
		valToIndex:           make(map[string]uint),
		validators:           vals,
		currentAeonEnd:       aeonEnd,
		entropyParams:        entropyParams,
		threshold:            dkgThreshold,
		startHeight:          validatorHeight,
		enableRecovery:       true,
		states:               make(map[dkgState]*state),
		currentState:         dkgStart,
		earlySecretShares:    make(map[uint]string),
		dryRunKeys:           make(map[string]DKGOutput),
		dryRunSignatures:     make(map[string]map[string]string),
		dryRunCount:          bits.NewBitArray(vals.Size()),
		encryptionKey:        dhKey,
		encryptionPublicKeys: make(map[uint][]byte),
		metrics:              NopMetrics(),
		slotProtocolEnforcer: slotProtocolEnforcer,
	}
	dkg.BaseService = *service.NewBaseService(nil, "DKG", dkg)

	if dkg.index() >= 0 {
		dkg.beaconService = mcl_cpp.NewBeaconSetupService(uint(len(dkg.validators.Validators)), uint(dkg.threshold), uint(dkg.index()))
	}
	// Set validator address to index
	for index, val := range dkg.validators.Validators {
		dkg.valToIndex[string(val.PubKey.Address())] = uint(index)
	}

	dkg.setInitialStateDuration()
	dkg.setStates()

	// If exit function failed before dry run then skip intermediate states and wait to see if DKG passes for everyone else
	dkg.onFailState = func(blockHeight int64) { dkg.proceedToNextState(waitForDryRun, false, blockHeight) }

	// notify the slot protocol enforcer of the new DKG details
	dkg.slotProtocolEnforcer.UpdateDKG(dkg)

	// Free beacon setup service when DKG is garbage collected
	runtime.SetFinalizer(dkg,
		func(dkg *DistributedKeyGeneration) {
			mcl_cpp.DeleteBeaconSetupService(dkg.beaconService)
		})

	return dkg
}

// Clear the state of the DKG as if it had just been initialised
func (dkg *DistributedKeyGeneration) ClearState() *DistributedKeyGeneration {
	newDkg := NewDistributedKeyGeneration(dkg.config, dkg.baseConfig, dkg.chainID, dkg.privValidator,
		dkg.encryptionKey, dkg.validatorHeight, dkg.dkgID, dkg.validators,
		dkg.currentAeonEnd, dkg.entropyParams, dkg.slotProtocolEnforcer)

	// Copy closures
	newDkg.onFailState = dkg.onFailState
	newDkg.sendMsgCallback = dkg.sendMsgCallback
	newDkg.dkgCompletionCallback = dkg.dkgCompletionCallback
	newDkg.evidenceHandler = dkg.evidenceHandler

	return newDkg
}

// Estimate of dkg run times from local computations
func (dkg *DistributedKeyGeneration) setInitialStateDuration() {
	numVal := len(dkg.validators.Validators)
	if numVal <= 100 {
		dkg.stateDuration = 5
	} else if numVal <= 200 {
		dkg.stateDuration = 10
	} else {
		dkg.stateDuration = int64(numVal)
	}
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

func (dkg *DistributedKeyGeneration) attachMetrics(metrics *Metrics) {
	dkg.metrics = metrics
}

func (dkg *DistributedKeyGeneration) setStates() {
	dkg.states[dkgStart] = newState(0, nil, func() bool {
		err := dkg.Start()
		return err == nil
	}, nil)

	if dkg.index() < 0 {
		dkg.states[waitForDryRun] = newState(dkgStatesWithDuration,
			nil,
			dkg.checkDryRuns,
			dkg.receivedAllDryRuns)
	} else {
		dkg.states[waitForEncryptionKeys] = newState(1,
			dkg.sendEncryptionKey,
			dkg.checkEncryptionKeys,
			dkg.receivedAllEncryptionKeys)
		dkg.states[waitForCoefficientsAndShares] = newState(1,
			dkg.sendSharesAndCoefficients,
			nil,
			dkg.beaconService.ReceivedAllCoefficientsAndShares)
		dkg.states[waitForComplaints] = newState(1,
			dkg.sendComplaints,
			nil,
			dkg.beaconService.ReceivedAllComplaints)
		dkg.states[waitForComplaintAnswers] = newState(1,
			dkg.sendComplaintAnswers,
			dkg.buildQual,
			dkg.beaconService.ReceivedAllComplaintAnswers)
		dkg.states[waitForQualCoefficients] = newState(1,
			dkg.sendQualCoefficients,
			nil,
			dkg.beaconService.ReceivedAllQualCoefficients)
		dkg.states[waitForQualComplaints] = newState(1,
			dkg.sendQualComplaints,
			dkg.beaconService.CheckQualComplaints,
			dkg.beaconService.ReceivedAllQualComplaints)
		dkg.states[waitForReconstructionShares] = newState(1,
			dkg.sendReconstructionShares,
			dkg.beaconService.RunReconstruction,
			dkg.beaconService.ReceivedAllReconstructionShares)
		dkg.states[waitForDryRun] = newState(1,
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
	dkg.metrics.DKGState.Set(float64(dkg.currentState))
	dkg.metrics.DKGIteration.Set(float64(dkg.dkgIteration))
	dkg.metrics.DKGFailures.Add(1)
	// Reset start time. +1 to ensure start is after the previous aeon end
	dkg.startHeight = dkg.startHeight + dkg.duration() + keylessOffset + 1
	// Increase dkg time
	newStateDuration := dkg.stateDuration + int64(float64(dkg.stateDuration)*dkgIterationDurationMultiplier)
	if newStateDuration <= maxDKGStateDuration {
		dkg.stateDuration = newStateDuration
	}
	// Dispatch empty keys to entropy generator. +keylessOffset needed at the end of aeonEnd to give app sufficient time to be
	// notified before next aeon start
	if dkg.dkgCompletionCallback != nil {
		dkg.dkgCompletionCallback(keylessAeonDetails(dkg.dkgID, dkg.validatorHeight,
			dkg.startHeight, dkg.startHeight+dkg.duration()+keylessOffset))
	}
	// Reset beaconService
	if dkg.index() >= 0 {
		mcl_cpp.DeleteBeaconSetupService(dkg.beaconService)
		dkg.beaconService = mcl_cpp.NewBeaconSetupService(uint(len(dkg.valToIndex)), dkg.threshold, uint(dkg.index()))
		dkg.setStates()
	}
	// Reset dkg details
	dkg.encryptionPublicKeys = make(map[uint][]byte)
	dkg.earlySecretShares = make(map[uint]string)
	dkg.dryRunKeys = make(map[string]DKGOutput)
	dkg.dryRunSignatures = make(map[string]map[string]string)
	dkg.dryRunCount = bits.NewBitArray(dkg.validators.Size())
	dkg.aeonKeys = nil

	// notify the slot protocol enforcer of the new DKG details
	dkg.slotProtocolEnforcer.UpdateDKG(dkg)

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
	// Process transactions
	for _, trx := range trxs {
		// Decode transaction
		msg := trx

		// Check msg is from validators and verify signature
		index, val := dkg.validators.GetByAddress(msg.FromAddress)

		if dkg.msgFromSelf(msg, index) && dkg.skipOwnMsg(msg.Type) {
			continue
		}

		if _, err := dkg.validateMessage(msg, index, val); err != nil {
			dkg.Logger.Debug("OnBlock: check msg", "height", blockHeight, "from", msg.FromAddress, "err", err)
			continue
		}

		switch msg.Type {
		case types.DKGEncryptionKey:
			if dkg.currentState > waitForEncryptionKeys {
				continue
			}
			if _, ok := dkg.encryptionPublicKeys[uint(index)]; !ok {
				dkg.encryptionPublicKeys[uint(index)] = []byte(msg.Data)
			}
		case types.DKGShare:
			if dkg.currentState > waitForCoefficientsAndShares {
				continue
			}
			dkg.onShares(msg.Data, uint(index))
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
			dkg.onDryRun(msg.Data, string(val.Address))
		default:
			dkg.Logger.Error("OnBlock: unknown DKGMessage", "type", msg.Type)
		}
	}

	dkg.checkTransition(blockHeight)
}

// There are 3 types of messages that the dkg needs to receive through the blocks, including
// its own. This is to ensure the following
// Encryption key : all nodes fail at the same DKG stage and evidence generated is accurate
// Complaint answer: everyone produces evidence at the same block height
// Dry run: all nodes finishes the dkg at the same time
func (dkg *DistributedKeyGeneration) skipOwnMsg(msgType types.DKGMessageType) bool {
	if msgType == types.DKGEncryptionKey || msgType == types.DKGComplaintAnswer || msgType == types.DKGDryRun {
		return false
	}
	return true
}

func (dkg *DistributedKeyGeneration) index() int {
	pubKey, err := dkg.privValidator.GetPubKey()
	if err != nil {
		dkg.Logger.Error("failed to retrieve public key", "err", err)
		return -1
	}

	index, _ := dkg.validators.GetByAddress(pubKey.Address())
	return index
}

func (dkg *DistributedKeyGeneration) msgFromSelf(msg *types.DKGMessage, index int) bool {
	return index == dkg.index()
}

// Validate that the message is a valid one to be taking part in the DKG
func (dkg *DistributedKeyGeneration) validateMessage(msg *types.DKGMessage, index int, val *types.Validator) (types.DKGMessageStatus, error) {

	// If it is a signed message from us, then assume it is correct since we are not malicious
	// otherwise, invalid!
	if dkg.msgFromSelf(msg, index) {
		if val.PubKey.VerifyBytes(msg.SignBytes(dkg.chainID), msg.Signature) {
			return types.OK, nil
		} else {
			return types.Invalid, fmt.Errorf("validateMessage: apparent message from self not signed correctly!")
		}
	}

	// Basic checks for all DKG messages
	if msg.Type >= types.DKGTypeCount {
		return types.Invalid, fmt.Errorf(fmt.Sprintf("validateMessage: msg failed as type out of bounds! %v", msg.Type))
	}
	if err := msg.ValidateBasic(); err != nil {
		return types.Invalid, fmt.Errorf("validateMessage: msg failed ValidateBasic err %v", err)
	}
	if index < 0 {
		return types.Invalid, fmt.Errorf("validateMessage: FromAddress not int validator set")
	}
	if msg.DKGID != dkg.dkgID {
		return types.Invalid, fmt.Errorf("validateMessage: invalid dkgID %v", msg.DKGID)
	}
	if msg.DKGIteration != dkg.dkgIteration {
		return types.Invalid, fmt.Errorf("validateMessage: incorrect dkgIteration %v", msg.DKGIteration)
	}
	if len(msg.ToAddress) != 0 {
		index, _ := dkg.validators.GetByAddress(msg.ToAddress)
		if index < 0 {
			return types.Invalid, fmt.Errorf("validateMessage: ToAddress not a valid validator")
		}
	}
	if !val.PubKey.VerifyBytes(msg.SignBytes(dkg.chainID), msg.Signature) {
		return types.Invalid, fmt.Errorf("validateMessage: failed signature verification")
	}

	if len(msg.ToAddress) == 0 {
		return types.OK, nil
	}

	// Check whether it is for us
	pubKey, err := dkg.privValidator.GetPubKey()
	if err != nil {
		return types.Invalid, fmt.Errorf("validatorMessage, failed to retrieve public Key %v", err)
	}
	if !bytes.Equal(msg.ToAddress, pubKey.Address()) {
		return types.NotForUs, fmt.Errorf("validateMessage: ToAddress not to us")
	}

	return types.OK, nil
}

func (dkg *DistributedKeyGeneration) checkTransition(blockHeight int64) {
	currentState := dkg.currentState

	if currentState == dkgFinish {
		dkg.metrics.DKGDuration.Set(float64(blockHeight - dkg.startHeight))
		return
	}
	if dkg.stateExpired(blockHeight) || dkg.states[currentState].checkTransition() {
		dkg.Logger.Debug("checkTransition: state change triggered", "height", blockHeight, "state", currentState, "stateExpired", dkg.stateExpired(blockHeight))
		if !dkg.states[currentState].onExit() {
			dkg.Logger.Error("checkTransition: failed onExit", "height", blockHeight, "state", currentState, "iteration", dkg.dkgIteration)
			if currentState == waitForDryRun {
				// If exit function for dry run failed then reset and restart DKG
				dkg.Stop()
				dkg.Reset()
			} else {
				dkg.submitEvidence(blockHeight)
				dkg.onFailState(blockHeight)
			}
			return
		}
		if currentState == dkgStart && dkg.index() < 0 {
			// If not in validators skip straight to waiting for DKG output
			dkg.proceedToNextState(waitForDryRun, false, blockHeight)
			return
		}
		dkg.proceedToNextState(currentState+1, true, blockHeight)
	}
}

func (dkg *DistributedKeyGeneration) proceedToNextState(nextState dkgState, runOnEntry bool, blockHeight int64) {

	// If the state we are going into is the first one, we can see if it is possible to load a DKG which has crashed.
	// Otherwise, we save our dkg details
	if dkg.enableRecovery {
		if nextState == waitForEncryptionKeys {
			loadDKG(dkg.baseConfig.DkgBackupFile(), dkg)
		} else if nextState == waitForDryRun || nextState == dkgFinish {
			// Just before going to the next state, save the DKG in its current form for crash recovery
			saveDKG(dkg.baseConfig.DkgBackupFile(), dkg)
		}
	}

	dkg.currentState = nextState
	dkg.metrics.DKGState.Set(float64(dkg.currentState))
	if runOnEntry {
		dkg.states[dkg.currentState].onEntry()
	}
	// Run check transition again in case we can proceed to the next state already
	dkg.checkTransition(blockHeight)
}

func (dkg *DistributedKeyGeneration) newDKGMessage(msgType types.DKGMessageType, data string, toAddress crypto.Address) *types.DKGMessage {
	if toAddress == nil {
		toAddress = []byte{}
	}
	pubKey, err := dkg.privValidator.GetPubKey()
	if err != nil {
		dkg.Logger.Error("failed to retrieve public key", "err", err)
		return &types.DKGMessage{}
	}
	newMsg := &types.DKGMessage{
		Type:         msgType,
		DKGID:        dkg.dkgID,
		DKGIteration: dkg.dkgIteration,
		FromAddress:  pubKey.Address(),
		ToAddress:    toAddress,
		Data:         data,
	}
	err = dkg.privValidator.SignDKGMessage(dkg.chainID, newMsg)
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

func (dkg *DistributedKeyGeneration) sendEncryptionKey() {
	dkg.Logger.Debug("sendEncryptionKey", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGEncryptionKey, string(dkg.encryptionKey.Public), nil)
}

func (dkg *DistributedKeyGeneration) sendSharesAndCoefficients() {
	dkg.Logger.Debug("sendSharesAndCoefficients", "iteration", dkg.dkgIteration)
	dkg.broadcastMsg(types.DKGCoefficient, dkg.beaconService.GetCoefficients(), nil)

	for validator, index := range dkg.valToIndex {
		if _, haveKeys := dkg.encryptionPublicKeys[index]; !haveKeys {
			continue
		}
		encryptedMsg, err := tmnoise.EncryptMsg(dkg.encryptionKey, dkg.encryptionPublicKeys[index], dkg.beaconService.GetShare(index))
		if err != nil {
			dkg.Logger.Error("sendShares: error encrypting share", "error", err.Error())
			continue
		}
		dkg.broadcastMsg(types.DKGShare, encryptedMsg, crypto.Address(validator))
	}

	// Add early shares
	for index, msg := range dkg.earlySecretShares {
		dkg.onShares(msg, index)
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
		nextAeonStart = dkgEnd + keylessOffset + 1
	}
	var err error
	dkg.aeonKeys, err = newAeonDetails(dkg.privValidator, dkg.validatorHeight, dkg.dkgID, &dkg.validators, aeonExecUnit,
		nextAeonStart, nextAeonStart+dkg.entropyParams.AeonLength-1)
	if err != nil {
		dkg.Logger.Error("computePublicKeys", "err", err.Error())
		dkg.aeonKeys = nil
		return
	}
	dkg.Logger.Debug("sendDryRun", "iteration", dkg.dkgIteration)
	msgToSign := string(cdc.MustMarshalBinaryBare(dkg.aeonKeys.dkgOutput()))
	signature := dkg.aeonKeys.aeonExecUnit.Sign(msgToSign, uint(dkg.index()))
	// Broadcast message to notify everyone of completion
	dryRun := DryRunSignature{
		PublicInfo:     *dkg.aeonKeys.dkgOutput(),
		SignatureShare: signature,
	}
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
			stateEndHeight += state.durationMultiplier * dkg.stateDuration
		}
	}
	return blockHeight >= stateEndHeight
}

func (dkg *DistributedKeyGeneration) duration() int64 {
	dkgLength := int64(0)
	for _, state := range dkg.states {
		dkgLength += state.durationMultiplier * dkg.stateDuration
	}
	return dkgLength
}

func (dkg *DistributedKeyGeneration) onDryRun(data string, validatorAddress string) {
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
		dkg.dryRunSignatures[msgSigned] = make(map[string]string)
	}
	index, _ := dkg.valToIndex[validatorAddress]
	if !dkg.dryRunCount.GetIndex(int(index)) {
		dkg.dryRunSignatures[msgSigned][validatorAddress] = dryRun.SignatureShare
		dkg.dryRunCount.SetIndex(int(index), true)
	}
}

func (dkg *DistributedKeyGeneration) receivedAllDryRuns() bool {
	return dkg.dryRunCount.IsFull()
}

func (dkg *DistributedKeyGeneration) checkDryRuns() bool {
	encodedOutput := ""
	requiredPassSize := uint(dkg.validators.Size() - dkg.validators.Size()/3)
	if requiredPassSize < dkg.threshold {
		requiredPassSize = dkg.threshold
	}
	for encodedKeys, signatures := range dkg.dryRunSignatures {
		if uint(len(signatures)) >= requiredPassSize {
			encodedOutput = encodedKeys
			// Should only be one set of keys which gets threshold signatures
			// if double messages are forbidden
			break
		}
	}

	if len(encodedOutput) == 0 {
		dkg.Logger.Error("checkDryRuns: not enough dry run signatures.", "needed", requiredPassSize)
		return false
	}

	// Check signatures with keys that have over threshold signature shares
	signatureShares := mcl_cpp.NewIntStringMap()
	defer mcl_cpp.DeleteIntStringMap(signatureShares)
	aeonFile := &AeonDetailsFile{
		PublicInfo: dkg.dryRunKeys[encodedOutput],
	}
	tempKeys, err := loadAeonDetails(aeonFile, &dkg.validators, dkg.privValidator)
	if err != nil {
		dkg.Logger.Error("checkDryRuns: error loading dry run aeon", "err", err)
		return false
	}
	for address, signature := range dkg.dryRunSignatures[encodedOutput] {
		index, _ := tempKeys.validators.GetByAddress(crypto.Address(address))
		if index < 0 {
			continue
		}
		if tempKeys.aeonExecUnit.Verify(encodedOutput, signature, uint(index)) {
			signatureShares.Set(uint(index), signature)
		}
	}

	if signatureShares.Size() < requiredPassSize {
		dkg.Logger.Error(fmt.Sprintf("checkDryRuns: not enough valid dry run signatures. Got %v. Wanted %v",
			signatureShares.Size(), requiredPassSize))
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

func (dkg *DistributedKeyGeneration) receivedAllEncryptionKeys() bool {
	return len(dkg.encryptionPublicKeys) == len(dkg.validators.Validators)
}

// checkEncryptionKeys ensures that the number of validators returning encryption keys is at least
// the pre-dkg threshold of dkg threshold + 1/3 validators
func (dkg *DistributedKeyGeneration) checkEncryptionKeys() bool {
	return len(dkg.encryptionPublicKeys) >= int(dkg.threshold)+(len(dkg.validators.Validators)/3)
}

func (dkg *DistributedKeyGeneration) onShares(msg string, index uint) {
	// If share is early, before we have entered this state, then save for adding later
	if dkg.currentState != waitForCoefficientsAndShares {
		dkg.earlySecretShares[index] = msg
		return
	}
	// Check for encryption key. Even if we don't have it we add share so that
	// dkg registers we have received a share from this node
	key, haveKey := dkg.encryptionPublicKeys[uint(index)]
	if !haveKey {
		dkg.Logger.Error(fmt.Sprintf("onShares: missing encryption key index %v", index))
	}
	decryptedShares, err := tmnoise.DecryptMsg(dkg.encryptionKey, key, msg)
	if err != nil {
		dkg.Logger.Error(fmt.Sprintf("onShares: error decrypting share index %v", index), "error", err.Error())
	}
	dkg.beaconService.OnShares(decryptedShares, uint(index))
}

func (dkg *DistributedKeyGeneration) submitEvidence(blockHeight int64) {
	if dkg.evidenceHandler == nil || dkg.index() < 0 {
		return
	}
	pubKey, _ := dkg.privValidator.GetPubKey()
	slashingFraction := float64(dkg.entropyParams.SlashingThresholdPercentage) * 0.01
	slashingThreshold := int64(slashingFraction * float64(dkg.validators.Size()))

	var err error
	for index := 0; index < dkg.validators.Size(); index++ {
		if index == dkg.index() {
			continue
		}
		if dkg.shouldSubmitEvidence(index) {
			addr, _ := dkg.validators.GetByIndex(index)
			ev := types.NewDKGEvidence(blockHeight, addr, pubKey.Address(), dkg.validatorHeight, dkg.dkgID, slashingThreshold)
			ev.ComplainantSignature, err = dkg.privValidator.SignEvidence(dkg.chainID, ev)
			if err != nil {
				dkg.Logger.Error("Error signing evidence", "err", err)
				return
			}
			dkg.Logger.Info("Add evidence for dkg failure", "height", blockHeight, "val", fmt.Sprintf("%X", addr))
			dkg.evidenceHandler(ev)
		}
	}
}

// Currently only submit evidence if dkg has failed due to insufficient encryption keys
// or due to qual failure
func (dkg *DistributedKeyGeneration) shouldSubmitEvidence(index int) bool {
	switch dkg.currentState {
	case waitForEncryptionKeys:
		_, haveKey := dkg.encryptionPublicKeys[uint(index)]
		return !haveKey
	case waitForComplaintAnswers:
		return !dkg.beaconService.InQual(uint(index))
	default:
		return false
	}
}

//-------------------------------------------------------------------------------------------

// DKGOutput is struct for broadcasting dkg completion info
type DKGOutput struct {
	KeyType         string   `json:"key_type"`
	GroupPublicKey  string   `json:"group_public_key"`
	PublicKeyShares []string `json:"public_key_shares"`
	Generator       string   `json:"generator"`
	ValidatorHeight int64    `json:"validator_height"`
	DKGID           int64    `json:"dkg_id"`
	Qual            []int64  `json:"qual"`
	Start           int64    `json:"start"`
	End             int64    `json:"end"`
}

// ValidateBasic for basic validity checking of dkg output
func (output *DKGOutput) ValidateBasic() error {
	if len(output.GroupPublicKey) != 0 {
		if len(output.Generator) == 0 {
			return fmt.Errorf("Empty generator")
		}
		if len(output.Qual) == 0 || len(output.Qual) > len(output.PublicKeyShares) {
			return fmt.Errorf("Qual size %v invalid. Expected non-zero qual less than public key shares %v", len(output.Qual), len(output.PublicKeyShares))
		}
	}
	if output.ValidatorHeight <= 0 {
		return fmt.Errorf("Invalid validator height %v", output.ValidatorHeight)
	}
	if output.DKGID < 0 {
		return fmt.Errorf("Invalid dkg id %v", output.DKGID)
	}
	if output.Start <= 0 || output.End < output.Start {
		return fmt.Errorf("Invalid start %v or end %v", output.Start, output.End)
	}
	return nil
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
	if len(dryRun.SignatureShare) == 0 || len(dryRun.SignatureShare) > types.MaxEntropyShareSize {
		return fmt.Errorf("Invalid signature share size %v", len(dryRun.SignatureShare))
	}
	return nil
}

//-------------------------------------------------------------------------------------------
// Below are functions for saving and recovery of the DKG in case of a crash

// When saving to a file, save only the relevant DKG information for recovery
type DistributedKeyGenerationFile struct {
	ChainID          string                         `json:"chain_id"`
	DkgID            int64                          `json:"dkg_id"`
	DkgIteration     int64                          `json:"dkg_it"`
	CurrentAeonEnd   int64                          `json:"current_aeon_end"`
	AeonKeys         *aeonDetails                   `json:"aeon_keys"`
	StartHeight      int64                          `json:"start_height"`
	CurrentState     dkgState                       `json:"current_state"`
	BeaconServiceSer string                         `json:"beacon_service_ser"`
	DryRunKeys       map[string]DKGOutput           `json:"dry_run_keys"`
	DryRunSignatures map[string]map[string]string   `json:"dry_run_signatures"`
	DryRunCount      *bits.BitArray                 `json:dry_run_count"`
}

func saveDKG(file string, dkg *DistributedKeyGeneration) {

	if dkg.beaconService == nil {
		dkg.Logger.Error("Attempted to save DKG but the beacon service was nil. Skipping.")
		return 
	}

	toWrite := DistributedKeyGenerationFile{dkg.chainID, dkg.dkgID, dkg.dkgIteration, dkg.currentAeonEnd, dkg.aeonKeys, dkg.startHeight, dkg.currentState, dkg.beaconService.Serialize(), dkg.dryRunKeys, dkg.dryRunSignatures, dkg.dryRunCount}

	jsonBytes, err := cdc.MarshalJSONIndent(toWrite, "", "  ")
	if err != nil {
		panic(err)
	}

	err = tempfile.WriteFileAtomic(file, jsonBytes, 0600)
	if err != nil {
		dkg.Logger.Error("Failure to write to file!", "err", err)
		panic(err)
	}
}

// Load the dkg from file iff it is a dkg from the future. This will overwrite certain fields in
// the dkg object with previously lost information
func loadDKG(filePath string, dkg *DistributedKeyGeneration) (err error) {

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("Failed to find file %v when attempting to load dkg", filePath))
	}

	jsonBytes, err := ioutil.ReadFile(filePath)
	if err != nil || len(jsonBytes) == 0 {
		return errors.New(fmt.Sprintf("Failed to read file! %v", filePath))
	}
	var dkgLoaded DistributedKeyGenerationFile

	err = cdc.UnmarshalJSON(jsonBytes, &dkgLoaded)

	if err != nil {
		return errors.New(fmt.Sprintf("Failed to unmarshal file! %v", jsonBytes))
	}

	// Only load (deserialise the beacon service) when it is
	// The same DKG, but in the future
	matches := true

	matches = matches && dkgLoaded.ChainID == dkg.chainID
	matches = matches && dkgLoaded.DkgID == dkg.dkgID
	matches = matches && dkgLoaded.DkgIteration == dkg.dkgIteration
	matches = matches && dkgLoaded.CurrentAeonEnd == dkg.currentAeonEnd
	matches = matches && dkgLoaded.StartHeight == dkg.startHeight
	matches = matches && dkgLoaded.CurrentState >= dkg.currentState

	if matches {
		dkg.beaconService.Deserialize(dkgLoaded.BeaconServiceSer)
	}

	return nil
}
