package beacon

import (
	"bytes"
	"fmt"
	"sync"

	cfg "github.com/tendermint/tendermint/config"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/crypto"
	//"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

type dkgState int

const (
	dkgStart dkgState = iota
	waitForCoefficientsAndShares
	waitForComplaints
	waitForComplaintAnswers
	waitForQualCoefficients
	waitForQualComplaints
	waitForReconstructionShares
	dkgFinish
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

//DistributedKeyGeneration handles dkg messages inside block for one dkg run
type DistributedKeyGeneration struct {
	cmn.BaseService
	mtx sync.RWMutex

	config       *cfg.ConsensusConfig
	chainID      string
	dkgID        int
	dkgIteration int

	privValidator types.PrivValidator
	valToIndex    map[string]uint // Need to convert crypto.Address into string for key
	validators    types.ValidatorSet
	threshold     int

	startHeight   int64
	states        map[dkgState]*state
	currentState  dkgState
	beaconService BeaconSetupService

	sendMsgCallback       func(tx *types.DKGMessage)
	dkgCompletionCallback func(*aeonDetails)
}

// NewDistributedKeyGeneration runs the DKG from messages encoded in transactions
func NewDistributedKeyGeneration(csConfig *cfg.ConsensusConfig, chain string, dkgRunID int,
	privVal types.PrivValidator, vals types.ValidatorSet, startH int64) *DistributedKeyGeneration {
	index, _ := vals.GetByAddress(privVal.GetPubKey().Address())
	if index < 0 {
		panic(fmt.Sprintf("NewDKG: privVal not in validator set"))
	}
	dkgThreshold := len(vals.Validators)/2 + 1
	dkg := &DistributedKeyGeneration{
		config:        csConfig,
		chainID:       chain,
		dkgID:         dkgRunID,
		dkgIteration:  0,
		privValidator: privVal,
		valToIndex:    make(map[string]uint),
		validators:    vals,
		threshold:     dkgThreshold,
		startHeight:   startH,
		states:        make(map[dkgState]*state),
		currentState:  dkgStart,
		beaconService: NewBeaconSetupService(uint(len(vals.Validators)), uint(dkgThreshold), uint(index)),
	}
	dkg.BaseService = *cmn.NewBaseService(nil, "DKG", dkg)

	// Set validator address to index
	for index, val := range dkg.validators.Validators {
		dkg.valToIndex[string(val.PubKey.Address())] = uint(index)
	}

	dkg.setStates()

	return dkg
}

// AttachMessageHandler sets the function for the DKG to send transactions to the mempool
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
	dkg.states[waitForCoefficientsAndShares] = newState(dkg.config.DKGStateDuration,
		dkg.sendSharesAndCoefficients,
		nil,
		dkg.beaconService.ReceivedAllCoefficientsAndShares)
	dkg.states[waitForComplaints] = newState(dkg.config.DKGStateDuration,
		dkg.sendComplaints,
		nil,
		dkg.beaconService.ReceivedAllComplaints)
	dkg.states[waitForComplaintAnswers] = newState(dkg.config.DKGStateDuration,
		dkg.sendComplaintAnswers,
		dkg.buildQual,
		dkg.beaconService.ReceivedAllComplaintAnswers)
	dkg.states[waitForQualCoefficients] = newState(dkg.config.DKGStateDuration,
		dkg.sendQualCoefficients,
		nil,
		dkg.beaconService.ReceivedAllQualCoefficients)
	dkg.states[waitForQualComplaints] = newState(dkg.config.DKGStateDuration,
		dkg.sendQualComplaints,
		dkg.beaconService.CheckQualComplaints,
		dkg.beaconService.ReceivedAllQualComplaints)
	dkg.states[waitForReconstructionShares] = newState(dkg.config.DKGStateDuration,
		dkg.sendReconstructionShares,
		dkg.beaconService.RunReconstruction,
		dkg.beaconService.ReceivedAllReconstructionShares)
	dkg.states[dkgFinish] = newState(0, dkg.computeKeys, nil, nil)
}

//OnReset overrides BaseService
func (dkg *DistributedKeyGeneration) OnReset() error {
	dkg.currentState = dkgStart
	dkg.dkgIteration++
	// Reset start time
	currentAeon := dkg.startHeight / dkg.config.AeonLength
	dkg.startHeight = dkg.startHeight + dkg.duration() + dkg.config.DKGResetDelay
	// If dkg runs into next aeon then reset start height to the normal dkg start
	// in that aeon
	dkgCompletionAeon := (dkg.startHeight + dkg.duration()) / dkg.config.AeonLength
	if dkgCompletionAeon != currentAeon {
		dkg.startHeight = dkg.config.AeonLength*(currentAeon+1) + dkg.config.DKGResetDelay
	}
	// Reset beaconService
	index := dkg.valToIndex[string(dkg.privValidator.GetPubKey().Address())]
	DeleteBeaconSetupService(dkg.beaconService)
	dkg.beaconService = NewBeaconSetupService(uint(len(dkg.valToIndex)), uint(dkg.threshold), uint(index))
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
			dkg.Logger.Error("OnBlock: check msg", "height", blockHeight, "msg", msg, "err", err)
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
		default:
			dkg.Logger.Error("OnBlock: unknown DKGMessage", "type", msg.Type)
		}
	}

	dkg.checkTransition(blockHeight)
}

func (dkg *DistributedKeyGeneration) index() uint {
	return dkg.valToIndex[string(dkg.privValidator.GetPubKey().Address())]
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
			// If exit functions fail then DKG has failed and we restart
			dkg.Logger.Error("checkTransition: failed onExit", "height", blockHeight, "state", dkg.currentState, "iteration", dkg.dkgIteration)
			dkg.Stop()
			dkg.Reset()
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
		if index != dkg.index() {
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

	if dkg.dkgCompletionCallback != nil {
		// Create new aeon details - start height at the moment is always set to be the start
		// of the next aeon
		currentAeon := (dkg.startHeight + dkg.duration()) / dkg.config.AeonLength
		nextAeonStart := (currentAeon + 1) * dkg.config.AeonLength
		aeonDetails := NewAeonDetails(&dkg.validators, dkg.privValidator, aeonExecUnit,
			nextAeonStart, nextAeonStart+dkg.config.AeonLength-1)
		dkg.dkgCompletionCallback(aeonDetails)
	}

	// Stop service so we do not process more blocks
	dkg.Stop()
}

func (dkg *DistributedKeyGeneration) stateExpired(blockHeight int64) bool {
	stateEndHeight := dkg.startHeight
	for i := dkgStart; i <= dkg.currentState; i++ {
		stateEndHeight += dkg.states[i].duration
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
