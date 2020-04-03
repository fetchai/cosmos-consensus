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

	sendMsgCallback func(tx *types.Tx) error
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
func (dkg *DistributedKeyGeneration) SetSendMsgCallback(callback func(tx *types.Tx) error) {
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
		dkg.checkTransition(blockHeight)
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
			shares := NewStringPair()
			defer DeleteStringPair(shares)
			shares.SetFirst(dataMsg.FirstShare)
			shares.SetSecond(dataMsg.SecondShare)
			dkg.beaconService.OnShares(shares, uint(index))
		case *DKGCoefficient:
			switch msg.Type {
			case types.DKGCoefficient:
				if dkg.currentState > waitForCoefficientsAndShares {
					continue
				}
				coefficients := NewStringVector()
				defer DeleteStringVector(coefficients)
				for i := 0; i < len(dataMsg.Coefficients); i++ {
					coefficients.Add(dataMsg.Coefficients[i])
				}
				dkg.beaconService.OnCoefficients(coefficients, uint(index))
			case types.DKGQualCoefficient:
				if dkg.currentState > waitForQualCoefficients {
					continue
				}
				coefficients := NewStringVector()
				defer DeleteStringVector(coefficients)
				for i := 0; i < len(dataMsg.Coefficients); i++ {
					coefficients.Add(dataMsg.Coefficients[i])
				}
				dkg.beaconService.OnQualCoefficients(coefficients, uint(index))
			default:
				dkg.Logger.Error("OnBlock: unknown DKGMessage", "type", msg.Type)
			}
		case *DKGComplaint:
			if msg.Type != types.DKGComplaint || dkg.currentState > waitForComplaints {
				continue
			}
			complaints := NewIntVector()
			defer DeleteIntVector(complaints)
			for i := 0; i < len(dataMsg.Complaints); i++ {
				complaints.Add(dataMsg.Complaints[i])
			}
			dkg.beaconService.OnComplaints(complaints, uint(index))
		case *DKGExposedShareList:
			switch msg.Type {
			case types.DKGComplaintAnswer:
				if dkg.currentState > waitForComplaintAnswers {
					continue
				}
				exposedShares := NewGoSharesExposedMap()
				defer DeleteGoSharesExposedMap(exposedShares)
				for i := 0; i < len(dataMsg.ExposedShares); i++ {
					keyValuePair := dataMsg.ExposedShares[i]
					pair := NewStringPair()
					defer DeleteStringPair(pair)
					pair.SetFirst(keyValuePair.Shares.FirstShare)
					pair.SetSecond(keyValuePair.Shares.SecondShare)
					exposedShares.Set(keyValuePair.Index, pair)
				}
				dkg.beaconService.OnComplaintAnswers(exposedShares, uint(index))
			case types.DKGQualComplaint:
				if dkg.currentState > waitForQualComplaints {
					continue
				}
				exposedShares := NewGoSharesExposedMap()
				defer DeleteGoSharesExposedMap(exposedShares)
				for i := 0; i < len(dataMsg.ExposedShares); i++ {
					keyValuePair := dataMsg.ExposedShares[i]
					pair := NewStringPair()
					defer DeleteStringPair(pair)
					pair.SetFirst(keyValuePair.Shares.FirstShare)
					pair.SetSecond(keyValuePair.Shares.SecondShare)
					exposedShares.Set(keyValuePair.Index, pair)
				}
				dkg.beaconService.OnQualComplaints(exposedShares, uint(index))
			case types.DKGReconstructionShare:
				if dkg.currentState > waitForReconstructionShares {
					continue
				}
				exposedShares := NewGoSharesExposedMap()
				defer DeleteGoSharesExposedMap(exposedShares)
				for i := 0; i < len(dataMsg.ExposedShares); i++ {
					keyValuePair := dataMsg.ExposedShares[i]
					pair := NewStringPair()
					defer DeleteStringPair(pair)
					pair.SetFirst(keyValuePair.Shares.FirstShare)
					pair.SetSecond(keyValuePair.Shares.SecondShare)
					exposedShares.Set(keyValuePair.Index, pair)
				}
				dkg.beaconService.OnReconstructionShares(exposedShares, uint(index))
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
		// Run check transition again in case we can proceed to the next state already
		if dkg.currentState == dkgFinish {
			return
		}
		dkg.checkTransition(blockHeight)
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
		trx := types.Tx(cdc.MustMarshalBinaryBare(msg))
		dkg.sendMsgCallback(&trx)
	}
}

func (dkg *DistributedKeyGeneration) sendSharesAndCoefficients() {
	coefficients := dkg.beaconService.GetCoefficients()
	coeffGo := make([]string, coefficients.Size())
	for i := 0; i < int(coefficients.Size()); i++ {
		coeffGo[i] = coefficients.Get(i)
	}
	coefficientMsg := dkg.newDKGMessage(types.DKGCoefficient, cdc.MustMarshalBinaryBare(&DKGCoefficient{
		Coefficients: coeffGo,
	}), []byte{})
	dkg.serialisedAndSendMsg(coefficientMsg)

	for validator, index := range dkg.valToIndex {
		shares := dkg.beaconService.GetShare(index)
		shareMsg := dkg.newDKGMessage(types.DKGShare, cdc.MustMarshalBinaryBare(&DKGSecretShare{
			FirstShare:  shares.GetFirst(),
			SecondShare: shares.GetSecond(),
		}), crypto.Address(validator))
		dkg.serialisedAndSendMsg(shareMsg)
	}
}

func (dkg *DistributedKeyGeneration) sendComplaints() {
	complaints := NewIntVector()
	dkg.beaconService.GetComplaints(complaints)
	complaintsGo := make([]uint, complaints.Size())
	for i := 0; i < int(complaints.Size()); i++ {
		complaintsGo[i] = complaints.Get(i)
	}
	complaintMsg := dkg.newDKGMessage(types.DKGComplaint, cdc.MustMarshalBinaryBare(&DKGComplaint{
		Complaints: complaintsGo,
	}), []byte{})
	dkg.serialisedAndSendMsg(complaintMsg)
}

func (dkg *DistributedKeyGeneration) sendComplaintAnswers() {
	dkg.beaconService.GetComplaintAnswers()
	exposedSharesGo := make([]DKGExposedShare, 0)
	// How to insert data??
	complaintAnswerMsg := dkg.newDKGMessage(types.DKGComplaintAnswer, cdc.MustMarshalBinaryBare(&DKGExposedShareList{
		ExposedShares: exposedSharesGo,
	}), []byte{})
	dkg.serialisedAndSendMsg(complaintAnswerMsg)
}

func (dkg *DistributedKeyGeneration) sendQualCoefficients() {
	coefficients := dkg.beaconService.GetQualCoefficients()
	coeffGo := make([]string, coefficients.Size())
	for i := 0; i < int(coefficients.Size()); i++ {
		coeffGo[i] = coefficients.Get(i)
	}
	qualCoeffMsg := dkg.newDKGMessage(types.DKGQualCoefficient, cdc.MustMarshalBinaryBare(&DKGCoefficient{
		Coefficients: coeffGo,
	}), []byte{})
	dkg.serialisedAndSendMsg(qualCoeffMsg)
}

func (dkg *DistributedKeyGeneration) sendQualComplaints() {
	dkg.beaconService.GetQualComplaints()
	exposedSharesGo := make([]DKGExposedShare, 0)
	qualComplaintMsg := dkg.newDKGMessage(types.DKGQualComplaint, cdc.MustMarshalBinaryBare(&DKGExposedShareList{
		ExposedShares: exposedSharesGo,
	}), []byte{})
	dkg.serialisedAndSendMsg(qualComplaintMsg)
}

func (dkg *DistributedKeyGeneration) sendReconstructionShares() {
	dkg.beaconService.GetReconstructionShares()
	exposedSharesGo := make([]DKGExposedShare, 0)
	reconstructionMsg := dkg.newDKGMessage(types.DKGReconstructionShare, cdc.MustMarshalBinaryBare(&DKGExposedShareList{
		ExposedShares: exposedSharesGo,
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
	cdc.RegisterConcrete(&DKGExposedShareList{}, "tendermint/DKGExposedShareList", nil)

}

type DKGSecretShare struct {
	FirstShare  string
	SecondShare string
}

func (share *DKGSecretShare) ValidateBasic() error {
	return nil
}

// String returns a string representation.
func (share *DKGSecretShare) String() string {
	return fmt.Sprintf("[DKGSecretShare %v/%v]", share.FirstShare, share.SecondShare)
}

type DKGCoefficient struct {
	Coefficients []string
}

func (coefficient *DKGCoefficient) ValidateBasic() error {
	return nil
}

type DKGComplaint struct {
	Complaints []uint
}

func (complaint *DKGComplaint) ValidateBasic() error {
	return nil
}

type DKGExposedShare struct {
	Index  uint
	Shares DKGSecretShare
}

func (share *DKGExposedShare) ValidateBasic() error {
	return nil
}

type DKGExposedShareList struct {
	ExposedShares []DKGExposedShare
}

func (exposedShare *DKGExposedShareList) ValidateBasic() error {
	return nil
}
