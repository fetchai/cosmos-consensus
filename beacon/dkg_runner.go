package beacon

import (
	"sync"
	"time"

	cmn "github.com/tendermint/tendermint/libs/common"
	cfg "github.com/tendermint/tendermint/config"
	//"github.com/tendermint/tendermint/libs/service"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

// DKGRunner manages the starting of the DKG each aeon with new validator sets and forwards on
// the output of the DKG. New DKGs are started at the beginning of every aeon assuming the previous
// DKG completed on time.
type DKGRunner struct {
	cmn.BaseService
	consensusConfig *cfg.ConsensusConfig
	chainID         string
	stateDB         dbm.DB
	privVal         types.PrivValidator
	messageHandler  tx_extensions.MessageHandler

	height       int64
	validators   types.ValidatorSet
	activeDKG    *DistributedKeyGeneration
	completedDKG bool
	valsUpdated  bool

	dkgCompletionCallback func(aeon *aeonDetails)

	mtx sync.Mutex
}

func NewDKGRunner(config *cfg.ConsensusConfig, chain string, db dbm.DB, val types.PrivValidator,
	blockHeight int64, vals types.ValidatorSet) *DKGRunner {
	dkgRunner := &DKGRunner{
		consensusConfig: config,
		chainID:         chain,
		stateDB:         db,
		privVal:         val,
		height:          blockHeight,
		validators:      vals,
		completedDKG:    false,
		valsUpdated:     true,
	}
	dkgRunner.BaseService = *cmn.NewBaseService(nil, "DKGRunner", dkgRunner)

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
	defer dkgRunner.mtx.Unlock()

	dkgRunner.height = blockHeight
	dkgRunner.valsUpdated = false
	if dkgRunner.activeDKG != nil {
		dkgRunner.activeDKG.OnBlock(blockHeight, trxs)
	}
}

// Routine for fetching validator updates from the state DB
func (dkgRunner *DKGRunner) validatorUpdatesRoutine() {

	for {
		if !dkgRunner.IsRunning() {
			dkgRunner.Logger.Debug("validatorUpdatesRoutine: exiting", "height", dkgRunner.height)
			return
		}

		dkgRunner.updateValidators()
		time.Sleep(100 * time.Millisecond)
	}
}

// Fetches validators for most recent block height from state DB and updates local validators. After updates
// checks if a new DKG should be started with the new validators
func (dkgRunner *DKGRunner) updateValidators() {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if dkgRunner.valsUpdated {
		return
	}

	newVals, err := sm.LoadValidators(dkgRunner.stateDB, dkgRunner.height)
	if err != nil {
		switch err.(type) {
		case *sm.ErrNoValSetForHeight:
			dkgRunner.Logger.Debug("updateValidators: ", "error", err.Error())
		default:
			dkgRunner.Logger.Error("updateValidators: unknown error loading vals", "error", err.Error())
		}
	} else {
		dkgRunner.Logger.Debug("updateValidators: vals updated", "height", dkgRunner.height)
		dkgRunner.validators = *newVals
		dkgRunner.valsUpdated = true
		dkgRunner.checkNextDKG()
	}
}

// Resets completed DKG and starts new one at the beginning of every aeon
func (dkgRunner *DKGRunner) checkNextDKG() {
	if dkgRunner.completedDKG {
		dkgRunner.activeDKG = nil
		dkgRunner.completedDKG = false
	}
	if dkgRunner.height%dkgRunner.consensusConfig.AeonLength == 0 {
		dkgRunner.startNewDKG()
	}
}

// Starts new DKG if old one has completed for those in the current validator set
func (dkgRunner *DKGRunner) startNewDKG() {
	aeon := int(dkgRunner.height / dkgRunner.consensusConfig.AeonLength)
	if dkgRunner.activeDKG != nil {
		dkgRunner.Logger.Error("startNewDKG: dkg already started", "aeon", aeon, "height", dkgRunner.height)
		return
	}
	if index, _ := dkgRunner.validators.GetByAddress(dkgRunner.privVal.GetPubKey().Address()); index < 0 {
		dkgRunner.Logger.Debug("startNewDKG: not in validators", "aeon", aeon, "height", dkgRunner.height)
		return
	}
	dkgRunner.Logger.Debug("startNewDKG: successful", "aeon", aeon, "height", dkgRunner.height)
	// Create new dkg with dkgID = aeon. New dkg starts DKGResetDelay after most recent block height
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.consensusConfig, dkgRunner.chainID,
		aeon, dkgRunner.privVal, dkgRunner.validators, dkgRunner.height+dkgRunner.consensusConfig.DKGResetDelay)
	// Set logger with dkgID and node index for debugging
	dkgLogger := dkgRunner.Logger.With("dkgID", dkgRunner.activeDKG.dkgID)
	dkgLogger.With("index", dkgRunner.activeDKG.index())
	dkgRunner.activeDKG.SetLogger(dkgLogger)
	// Set message handler for sending DKG transactions
	dkgRunner.activeDKG.SetSendMsgCallback(func(msg *types.DKGMessage) {
		dkgRunner.messageHandler.SubmitSpecialTx(msg)
	})
	// Mark dkg completion so so that activeDKG can be reset
	dkgRunner.activeDKG.SetDkgCompletionCallback(func(keys *aeonDetails) {
		dkgRunner.completedDKG = true
		if dkgRunner.dkgCompletionCallback != nil {
			dkgRunner.dkgCompletionCallback(keys)
		}
	})
}
