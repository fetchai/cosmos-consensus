package beacon

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	amino "github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/libs/service"
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

	dkgTypicalStateDuration = int64(10)
	dkgResetWait            = int64(5) // Wait time in blocks before next dkg iteration
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
	service.BaseService
	mtx sync.RWMutex

	privValidator types.PrivValidator
	valToIndex    map[string]uint // Need to convert crypto.Address into string for key
	validators    *types.ValidatorSet
	threshold     int

	startHeight   int64
	states        map[dkgState]*state
	currentState  dkgState
	beaconService BeaconSetupService

	dkgID        int
	dkgIteration int
	chainID      string

	sendMsgCallback func(tx types.Tx) error
}

// NewDistributedKeyGeneration
func NewDistributedKeyGeneration(privVal types.PrivValidator, vals *types.ValidatorSet, startH int64, dkgRunID int, chain string) *DistributedKeyGeneration {
	index, _ := vals.GetByAddress(privVal.GetPubKey().Address())
	if index < 0 {
		panic(fmt.Sprintf("NewDKG: privVal not in validator set"))
	}
	dkgThreshold := len(vals.Validators)/2 + 1
	dkg := &DistributedKeyGeneration{
		privValidator: privVal,
		valToIndex:    make(map[string]uint),
		validators:    vals,
		threshold:     dkgThreshold,
		startHeight:   startH,
		states:        make(map[dkgState]*state),
		currentState:  dkgStart,
		beaconService: NewBeaconSetupService(uint(len(vals.Validators)), uint(dkgThreshold), uint(index)),
		dkgID:         dkgRunID,
		dkgIteration:  0,
		chainID:       chain,
	}
	dkg.BaseService = *service.NewBaseService(nil, "DKG", dkg)

	// Set validator address to index
	for index, val := range dkg.validators.Validators {
		dkg.valToIndex[string(val.PubKey.Address())] = uint(index)
	}

	dkg.setStates()

	return dkg
}

// SetSendMsgCallback sets the function for the DKG to send transactions to the mempool
func (dkg *DistributedKeyGeneration) SetSendMsgCallback(callback func(tx types.Tx) error) {
	dkg.mtx.Lock()
	defer dkg.mtx.Unlock()

	dkg.sendMsgCallback = callback
}

func (dkg *DistributedKeyGeneration) setStates() {
	dkg.states[dkgStart] = newState(0, nil, func() bool {
		err := dkg.Start()
		return err == nil
	}, nil)
	dkg.states[waitForCoefficientsAndShares] = newState(dkgTypicalStateDuration, dkg.sendSharesAndCoefficients, nil, dkg.beaconService.ReceivedAllCoefficientsAndShares)
	dkg.states[waitForComplaints] = newState(dkgTypicalStateDuration, dkg.sendComplaints, nil, dkg.beaconService.ReceivedAllComplaints)
	dkg.states[waitForComplaintAnswers] = newState(dkgTypicalStateDuration, dkg.sendComplaintAnswers, dkg.buildQual, dkg.beaconService.ReceivedAllComplaintAnswers)
	dkg.states[waitForQualCoefficients] = newState(dkgTypicalStateDuration, dkg.sendQualCoefficients, nil, dkg.beaconService.ReceivedAllQualCoefficients)
	dkg.states[waitForQualComplaints] = newState(dkgTypicalStateDuration, dkg.sendQualComplaints, dkg.beaconService.CheckQualComplaints, dkg.beaconService.ReceivedAllQualComplaints)
	dkg.states[waitForReconstructionShares] = newState(dkgTypicalStateDuration, dkg.sendReconstructionShares, dkg.beaconService.RunReconstruction, dkg.beaconService.ReceivedAllReconstructionShares)
	dkg.states[dkgFinish] = newState(0, dkg.computeKeys, nil, nil)
}

//OnStart implements BaseService
func (dkg *DistributedKeyGeneration) OnStart() error { return nil }

//OnStop implements BaseService
func (dkg *DistributedKeyGeneration) OnStop() {}

//OnBlock processes DKG messages from a block
func (dkg *DistributedKeyGeneration) OnBlock(blockHeight int64, trxs []*types.Tx) {
	dkg.mtx.Lock()
	defer dkg.mtx.Unlock()

	if !dkg.IsRunning() {
		return
	}
	// Process transactions
	for _, trx := range trxs {
		// Decode transaction
		msg := &types.DKGMessage{}
		err := cdc.UnmarshalBinaryBare([]byte(*trx), msg)
		if err != nil {
			dkg.Logger.Error("OnBlock: decode tx", "height", blockHeight, "msg", msg, "err", err)
			continue
		}

		// Check msg is from validators and verify signature
		index, val := dkg.validators.GetByAddress(msg.FromAddress)
		if err = dkg.checkMsg(msg, index, val); err != nil {
			dkg.Logger.Error("OnBlock: check msg", "height", blockHeight, "msg", msg, "err", err)
			continue
		}
		// Decode data field
		dataMsg, err := decodeMsg(msg.Data)
		if err != nil {
			dkg.Logger.Error("OnBlock: decode data", "height", blockHeight, "data", dataMsg, "err", err)
			continue
		}
		// Basic dataMsg validation
		if err = dataMsg.ValidateBasic(); err != nil {
			dkg.Logger.Error("OnBlock: data basic validation", "height", blockHeight, "data", dataMsg, "err", err)
			continue
		}

		switch dataMsg := dataMsg.(type) {
		case *DKGSecretShare:
			if msg.Type != types.DKGShare || dkg.currentState > waitForCoefficientsAndShares {
				continue
			}
			dkg.beaconService.OnShares(dataMsg.shares, uint(index))
		case *DKGCoefficient:
			switch msg.Type {
			case types.DKGCoefficient:
				if dkg.currentState > waitForCoefficientsAndShares {
					continue
				}
				dkg.beaconService.OnCoefficients(dataMsg.coefficients, uint(index))
			case types.DKGQualCoefficient:
				if dkg.currentState > waitForQualCoefficients {
					continue
				}
				dkg.beaconService.OnQualCoefficients(dataMsg.coefficients, uint(index))
			default:
				dkg.Logger.Error("OnBlock: unknown DKGMessage", "type", msg.Type)
			}
		case *DKGExposedShare:
			switch msg.Type {
			case types.DKGComplaintAnswer:
				if dkg.currentState > waitForComplaintAnswers {
					continue
				}
				dkg.beaconService.OnComplaintAnswers(dataMsg.exposedShares, uint(index))
			case types.DKGQualComplaint:
				if dkg.currentState > waitForQualComplaints {
					continue
				}
				dkg.beaconService.OnQualComplaints(dataMsg.exposedShares, uint(index))
			case types.DKGReconstructionShare:
				if dkg.currentState > waitForReconstructionShares {
					continue
				}
				dkg.beaconService.OnReconstructionShares(dataMsg.exposedShares, uint(index))
			default:
				dkg.Logger.Error("OnBlock: unknown DKGMessage", "type", msg.Type)
			}
		default:
			dkg.Logger.Error("OnBlock: unknown DKG data", "type", reflect.TypeOf(dataMsg))
		}

	}

	dkg.checkTransition(blockHeight)
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
	if dkg.stateExpired(blockHeight) || dkg.states[dkg.currentState].checkTransition() {
		dkg.Logger.Debug("checkTransition: state change triggered", "height", blockHeight, "state", dkg.currentState)
		if !dkg.states[dkg.currentState].onExit() {
			// If exit functions fail then DKG has failed and we restart
			dkg.Logger.Error("checkTransition: failed onExit", "height", blockHeight, "state", dkg.currentState, "iteration", dkg.dkgIteration)
			dkg.currentState = dkgStart
			dkg.dkgIteration++
			// Reset start time
			dkg.startHeight = dkg.startHeight + dkg.duration() + dkgResetWait
			// Reset beaconService
			index := dkg.valToIndex[string(dkg.privValidator.GetPubKey().Address())]
			dkg.beaconService = NewBeaconSetupService(uint(len(dkg.valToIndex)), uint(dkg.threshold), uint(index))
			return
		}
		dkg.currentState++
		dkg.states[dkg.currentState].onEntry()
	} else {
		dkg.Logger.Debug("checkTransition: no state change", "height", blockHeight, "state", dkg.currentState, "iteration", dkg.dkgIteration)
	}
}

func (dkg *DistributedKeyGeneration) newDKGMessage(msgType types.DKGMessageType, data []byte, toAddress crypto.Address) *types.DKGMessage {
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

func (dkg *DistributedKeyGeneration) serialisedAndSendMsg(msg *types.DKGMessage) {
	if dkg.sendMsgCallback != nil {
		dkg.sendMsgCallback(types.Tx(cdc.MustMarshalBinaryBare(msg)))
	}
}

func (dkg *DistributedKeyGeneration) sendSharesAndCoefficients() {
	coefficientMsg := dkg.newDKGMessage(types.DKGCoefficient, cdc.MustMarshalBinaryBare(&DKGCoefficient{
		coefficients: dkg.beaconService.GetCoefficients(),
	}), []byte{})
	dkg.serialisedAndSendMsg(coefficientMsg)

	for validator, index := range dkg.valToIndex {
		shareMsg := dkg.newDKGMessage(types.DKGShare, cdc.MustMarshalBinaryBare(&DKGSecretShare{
			shares: dkg.beaconService.GetShare(index),
		}), crypto.Address(validator))
		dkg.serialisedAndSendMsg(shareMsg)
	}
}

func (dkg *DistributedKeyGeneration) sendComplaints() {
	complaints := NewIntVector()
	dkg.beaconService.GetComplaints(complaints)
	complaintMsg := dkg.newDKGMessage(types.DKGComplaint, cdc.MustMarshalBinaryBare(&DKGComplaint{
		complaints: complaints,
	}), []byte{})
	dkg.serialisedAndSendMsg(complaintMsg)
}

func (dkg *DistributedKeyGeneration) sendComplaintAnswers() {
	complaintAnswerMsg := dkg.newDKGMessage(types.DKGComplaintAnswer, cdc.MustMarshalBinaryBare(&DKGExposedShare{
		exposedShares: dkg.beaconService.GetComplaintAnswers(),
	}), []byte{})
	dkg.serialisedAndSendMsg(complaintAnswerMsg)
}

func (dkg *DistributedKeyGeneration) sendQualCoefficients() {
	qualCoeffMsg := dkg.newDKGMessage(types.DKGQualCoefficient, cdc.MustMarshalBinaryBare(&DKGCoefficient{
		coefficients: dkg.beaconService.GetQualCoefficients(),
	}), []byte{})
	dkg.serialisedAndSendMsg(qualCoeffMsg)
}

func (dkg *DistributedKeyGeneration) sendQualComplaints() {
	qualComplaintMsg := dkg.newDKGMessage(types.DKGQualComplaint, cdc.MustMarshalBinaryBare(&DKGExposedShare{
		exposedShares: dkg.beaconService.GetQualComplaints(),
	}), []byte{})
	dkg.serialisedAndSendMsg(qualComplaintMsg)
}

func (dkg *DistributedKeyGeneration) sendReconstructionShares() {
	reconstructionMsg := dkg.newDKGMessage(types.DKGReconstructionShare, cdc.MustMarshalBinaryBare(&DKGExposedShare{
		exposedShares: dkg.beaconService.GetReconstructionShares(),
	}), []byte{})
	dkg.serialisedAndSendMsg(reconstructionMsg)
}

func (dkg *DistributedKeyGeneration) buildQual() bool {
	qual := dkg.beaconService.BuildQual()
	if qual.Size() == 0 {
		dkg.Logger.Info("buildQual: DKG failed", "iteration", dkg.dkgIteration)
		return false
	}
	return true
}

func (dkg *DistributedKeyGeneration) computeKeys() {
	dkg.beaconService.ComputePublicKeys()

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

//-----------------------------------------------------------------------------
// Messages

// RegisterDKGMessages registers dkg messages
func RegisterDKGMessages(cdc *amino.Codec) {
	cdc.RegisterConcrete(&DKGSecretShare{}, "tendermint/DKGSecretShare", nil)
	cdc.RegisterConcrete(&DKGCoefficient{}, "tendermint/DKGCoefficient", nil)
	cdc.RegisterConcrete(&DKGComplaint{}, "tendermint/DKGComplaint", nil)
	cdc.RegisterConcrete(&DKGExposedShare{}, "tendermint/DKGExposedShare", nil)
}

type DKGSecretShare struct {
	shares StringPair
}

func (share *DKGSecretShare) ValidateBasic() error {
	return nil
}

type DKGCoefficient struct {
	coefficients StringVector
}

func (coefficient *DKGCoefficient) ValidateBasic() error {
	return nil
}

type DKGComplaint struct {
	complaints IntVector
}

func (complaint *DKGComplaint) ValidateBasic() error {
	return nil
}

type DKGExposedShare struct {
	exposedShares GoSharesExposedMap
}

func (exposedShare *DKGExposedShare) ValidateBasic() error {
	return nil
}
