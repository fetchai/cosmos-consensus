package beacon

import (
	"fmt"
	"sync"
	"time"

	cfg "github.com/tendermint/tendermint/config"
	cmn "github.com/tendermint/tendermint/libs/common"

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
	aeonStart    int64 // next entropy generation start
	aeonEnd      int64 // next entropy generation end
	validators   types.ValidatorSet
	activeDKG    *DistributedKeyGeneration
	completedDKG bool
	valsUpdated  bool
	dkgCounter   int

	dkgCompletionCallback func(aeon *aeonDetails)

	mtx sync.Mutex
}

func NewDKGRunner(config *cfg.ConsensusConfig, chain string, db dbm.DB, val types.PrivValidator,
	blockHeight int64) *DKGRunner {
	dkgRunner := &DKGRunner{
		consensusConfig: config,
		chainID:         chain,
		stateDB:         db,
		privVal:         val,
		height:          blockHeight,
		aeonStart:       -1,
		aeonEnd:         -1,
		completedDKG:    false,
		dkgCounter:      0,
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

// SetCurrentAeon sets the entropy generation aeon currently active
func (dkgRunner *DKGRunner) SetCurrentAeon(start int64, end int64) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.aeonStart = start
	dkgRunner.aeonEnd = end
}

// OnStart overrides BaseService. Starts first DKG.
func (dkgRunner *DKGRunner) OnStart() error {
	dkgRunner.checkNextDKG()
	return nil
}

// OnBlock is callback in messageHandler for DKG messages included in a particular block
func (dkgRunner *DKGRunner) OnBlock(blockHeight int64, entropy types.ThresholdSignature, trxs []*types.DKGMessage) {
	dkgRunner.mtx.Lock()
	dkgRunner.height = blockHeight
	dkgRunner.valsUpdated = false

	if len(entropy) != 0 && blockHeight > dkgRunner.aeonEnd {
		// DKG should not be stale
		panic(fmt.Errorf("Unexpected entropy in block %v, aeon end %v", blockHeight, dkgRunner.aeonEnd))
	} else if dkgRunner.activeDKG != nil {
		dkgRunner.mtx.Unlock()
		dkgRunner.activeDKG.OnBlock(blockHeight, trxs)
		dkgRunner.mtx.Lock()
	}
	dkgRunner.checkNextDKG()
	dkgRunner.mtx.Unlock()
}

// Returns validators for height from state DB
func (dkgRunner *DKGRunner) findValidators(height int64) *types.ValidatorSet {
	for {
		if !dkgRunner.IsRunning() {
			dkgRunner.Logger.Debug("findValidators: exiting", "height", dkgRunner.height)
			return nil
		}

		newVals, err := sm.LoadValidators(dkgRunner.stateDB, height)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			dkgRunner.Logger.Debug("findValidators: vals updated", "height", height)
			return newVals
		}
	}
}

// Resets completed DKG and starts new one for next aeon
func (dkgRunner *DKGRunner) checkNextDKG() {
	if dkgRunner.completedDKG {
		dkgRunner.activeDKG = nil
		dkgRunner.completedDKG = false
	}

	// Start new dkg if there is currently no aeon active and if we are in the next
	// aeon
	if dkgRunner.activeDKG == nil && dkgRunner.height >= dkgRunner.aeonStart {
		// Set height at which validators are determined
		validatorHeight := dkgRunner.aeonStart
		if validatorHeight < 0 {
			// Only time when there is no previous aeon is first dkg from genesis
			validatorHeight = 1
		}
		vals := dkgRunner.findValidators(validatorHeight)
		if vals != nil {
			dkgRunner.startNewDKG(validatorHeight, vals)
		}
	}
}

// Starts new DKG if old one has completed for those in the current validator set
func (dkgRunner *DKGRunner) startNewDKG(validatorHeight int64, validators *types.ValidatorSet) {
	if index, _ := validators.GetByAddress(dkgRunner.privVal.GetPubKey().Address()); index < 0 {
		dkgRunner.Logger.Debug("startNewDKG: not in validators", "height", validatorHeight)
		return
	}
	dkgRunner.Logger.Debug("startNewDKG: successful", "height", validatorHeight)
	// Create new dkg with dkgID = aeon. New dkg starts DKGResetDelay after most recent block height
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.consensusConfig, dkgRunner.chainID,
		dkgRunner.dkgCounter, dkgRunner.privVal, validatorHeight, *validators, dkgRunner.aeonEnd)
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
