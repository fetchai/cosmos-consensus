package beacon

import (
	"sync"
	"time"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/service"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

// DKGRunner manages the starting of the DKG each aeon with new validator sets and forwards on
// the output of the DKG. New DKGs are started at the beginning of every aeon assuming the previous
// DKG completed on time.
type DKGRunner struct {
	service.BaseService
	consensusConfig *cfg.ConsensusConfig
	chainID         string
	stateDB         dbm.DB
	privVal         types.PrivValidator
	messageHandler  tx_extensions.MessageHandler

	height               int64
	aeonStart            int64 // next entropy generation start
	aeonEnd              int64 // next entropy generation end
	validators           types.ValidatorSet
	activeDKG            *DistributedKeyGeneration
	completedDKG         bool
	valsAndParamsUpdated bool
	dkgCounter           int
	nextAeonLength       int64

	dkgCompletionCallback func(aeon *aeonDetails)

	mtx sync.Mutex
}

// NewDKGRunner creates struct for starting new DKGs
func NewDKGRunner(config *cfg.ConsensusConfig, chain string, db dbm.DB, val types.PrivValidator,
	blockHeight int64, vals types.ValidatorSet, aeonLength int64) *DKGRunner {
	dkgRunner := &DKGRunner{
		consensusConfig:      config,
		chainID:              chain,
		stateDB:              db,
		privVal:              val,
		height:               blockHeight,
		aeonStart:            -1,
		aeonEnd:              -1,
		validators:           vals,
		completedDKG:         false,
		valsAndParamsUpdated: true,
		dkgCounter:           0,
		nextAeonLength:       aeonLength,
	}
	dkgRunner.BaseService = *service.NewBaseService(nil, "DKGRunner", dkgRunner)

	return dkgRunner
}

// SetDKGCompletionCallback for dispatching dkg output
func (dkgRunner *DKGRunner) SetDKGCompletionCallback(callback func(aeon *aeonDetails)) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.dkgCompletionCallback = callback
}

// AttachMessageHandler for sending DKG messages to the mempool and receiving DKG messages in
// blocks
func (dkgRunner *DKGRunner) AttachMessageHandler(handler tx_extensions.MessageHandler) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.messageHandler = handler
	// When DKG TXs are seen, they should call OnBlock
	dkgRunner.messageHandler.WhenChainTxSeen(dkgRunner.OnBlock)
}

// SetCurrentAeon sets the entropy generation aeon currently active
func (dkgRunner *DKGRunner) SetCurrentAeon(start int64, end int64) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.aeonStart = start
	dkgRunner.aeonEnd = end
}

// OnStart overrides BaseService. Starts first DKG and fetching of validator updates
func (dkgRunner *DKGRunner) OnStart() error {
	dkgRunner.checkNextDKG()
	// Start go routine for subscription
	go dkgRunner.validatorUpdatesRoutine()
	return nil
}

// OnBlock is callback in messageHandler for DKG messages included in a particular block
func (dkgRunner *DKGRunner) OnBlock(blockHeight int64, trxs []*types.DKGMessage) {
	dkgRunner.mtx.Lock()
	dkgRunner.height = blockHeight
	dkgRunner.valsAndParamsUpdated = false
	if dkgRunner.activeDKG != nil {
		dkgRunner.mtx.Unlock()
		dkgRunner.activeDKG.OnBlock(blockHeight, trxs)
		return
	}
	dkgRunner.mtx.Unlock()
}

// Routine for fetching validator updates from the state DB
func (dkgRunner *DKGRunner) validatorUpdatesRoutine() {

	for {
		if !dkgRunner.IsRunning() {
			dkgRunner.Logger.Debug("validatorUpdatesRoutine: exiting", "height", dkgRunner.height)
			return
		}

		dkgRunner.updateValidatorsAndParams()
		time.Sleep(100 * time.Millisecond)
	}
}

// Fetches validators for most recent block height from state DB and updates local validators. After updates
// checks if a new DKG should be started with the new validators
func (dkgRunner *DKGRunner) updateValidatorsAndParams() {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if dkgRunner.valsAndParamsUpdated {
		return
	}

	newParams, err1 := sm.LoadConsensusParams(dkgRunner.stateDB, dkgRunner.height)
	newVals, err2 := sm.LoadValidators(dkgRunner.stateDB, dkgRunner.height)
	// Only update and check for next DKG when both the validators and aeon length
	// have been updated to that of the latest state
	if err1 != nil {
		switch err1.(type) {
		case *sm.ErrNoConsensusParamsForHeight:
			dkgRunner.Logger.Debug("updateValidatorsAndParams: ", "error", err1.Error())
		default:
			dkgRunner.Logger.Error("updateValidatorsAndParams: unknown error loading params", "error", err1.Error())
		}
	} else if err2 != nil {
		switch err2.(type) {
		case *sm.ErrNoValSetForHeight:
			dkgRunner.Logger.Debug("updateValidatorsAndParams: ", "error", err2.Error())
		default:
			dkgRunner.Logger.Error("updateValidatorsAndParams: unknown error loading vals", "error", err2.Error())
		}
	} else {
		dkgRunner.Logger.Debug("updateValidators: vals and params updated", "height", dkgRunner.height)
		dkgRunner.nextAeonLength = newParams.Entropy.AeonLength
		dkgRunner.validators = *newVals
		dkgRunner.valsAndParamsUpdated = true
		dkgRunner.checkNextDKG()
	}
}

// Resets completed DKG and starts new one at the beginning of every aeon
func (dkgRunner *DKGRunner) checkNextDKG() {
	if dkgRunner.completedDKG {
		dkgRunner.activeDKG = nil
		dkgRunner.completedDKG = false
	}
	// Start new dkg if there is currently no aeon active or if we are at the
	// beginning of a new aeon
	if dkgRunner.aeonStart == -1 || dkgRunner.height == dkgRunner.aeonStart {
		dkgRunner.startNewDKG()
	}
}

// Starts new DKG if old one has completed for those in the current validator set
func (dkgRunner *DKGRunner) startNewDKG() {
	if dkgRunner.activeDKG != nil {
		dkgRunner.Logger.Error("startNewDKG: dkg already started", "height", dkgRunner.height)
		return
	}
	if index, _ := dkgRunner.validators.GetByAddress(dkgRunner.privVal.GetPubKey().Address()); index < 0 {
		dkgRunner.Logger.Debug("startNewDKG: not in validators", "height", dkgRunner.height)
		return
	}
	dkgRunner.Logger.Debug("startNewDKG: successful", "height", dkgRunner.height)
	// Create new dkg with dkgID = aeon. New dkg starts DKGResetDelay after most recent block height
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.consensusConfig, dkgRunner.chainID,
		dkgRunner.dkgCounter, dkgRunner.privVal, dkgRunner.validators,
		dkgRunner.height+dkgRunner.consensusConfig.DKGResetDelay, dkgRunner.aeonEnd, dkgRunner.nextAeonLength)
	dkgRunner.dkgCounter++
	// Set logger with dkgID and node index for debugging
	dkgLogger := dkgRunner.Logger.With("dkgID", dkgRunner.activeDKG.dkgID)
	dkgLogger.With("index", dkgRunner.activeDKG.index())
	dkgRunner.activeDKG.SetLogger(dkgLogger)
	// Set message handler for sending DKG transactions
	dkgRunner.activeDKG.SetSendMsgCallback(func(msg *types.DKGMessage) {
		dkgRunner.messageHandler.SubmitSpecialTx(msg)
	})
	// Mark dkg completion so so that activeDKG can be reset and set start and end
	// of next entropy aeon
	dkgRunner.activeDKG.SetDkgCompletionCallback(func(keys *aeonDetails) {
		dkgRunner.completedDKG = true
		dkgRunner.SetCurrentAeon(keys.Start, keys.End)
		if dkgRunner.dkgCompletionCallback != nil {
			dkgRunner.dkgCompletionCallback(keys)
		}
	})
}
