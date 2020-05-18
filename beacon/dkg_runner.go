package beacon

import (
	"fmt"
	"sync"
	"time"

	"github.com/flynn/noise"
	cfg "github.com/tendermint/tendermint/config"
	cmn "github.com/tendermint/tendermint/libs/common"
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
	dkgRunner    int
	dkgCounter   int

	dkgCompletionCallback func(aeon *aeonDetails)
	fastSync              bool

	encryptionKey noise.DHKey

	mtx     sync.Mutex
	metrics *Metrics
}

// NewDKGRunner creates struct for starting new DKGs
func NewDKGRunner(config *cfg.ConsensusConfig, chain string, db dbm.DB, val types.PrivValidator,
	encryptionKey noise.DHKey, blockHeight int64) *DKGRunner {
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
		metrics:         NopMetrics(),
		fastSync:        false,
		encryptionKey:   encryptionKey,
	}
	dkgRunner.BaseService = *cmn.NewBaseService(nil, "DKGRunner", dkgRunner)

	return dkgRunner
}

func (dkgRunner *DKGRunner) AttachMetrics(metrics *Metrics) {

	if dkgRunner != nil {
		dkgRunner.metrics = metrics
	}
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

// FastSync runs a dkg from block messages up to current block height
// for catch up
func (dkgRunner *DKGRunner) FastSync(blockStore sm.BlockStoreRPC) error {
	if dkgRunner.IsRunning() {
		return fmt.Errorf("FastSync: dkgRunner running!")
	}

	dkgHeight := dkgRunner.aeonStart
	if dkgHeight < 0 {
		dkgHeight = 1
	}
	if dkgRunner.height > dkgHeight {
		dkgRunner.Logger.Debug("FastSync: starting", "blockHeight", dkgRunner.height, "dkgStartHeight", dkgHeight)
		dkgRunner.fastSync = true
		dkgRunner.checkNextDKG()
		if dkgRunner.activeDKG == nil {
			return fmt.Errorf("FastSync: failed to start new dkg")
		}
		for dkgRunner.height > dkgHeight {
			// Load transactions from block
			block := blockStore.LoadBlock(dkgHeight)
			// Play transactions to DKG
			if block == nil {
				return fmt.Errorf("FastSync: nil block returned at height %v", dkgHeight)
			}
			dkgRunner.messageHandler.BeginBlock(block.Header.Entropy.GroupSignature)
			for _, trx := range block.Data.Txs {
				if tx_extensions.IsDKGRelated(trx) {
					dkgRunner.messageHandler.SpecialTxSeen(trx)
				}
			}
			dkgRunner.messageHandler.EndBlock(block.Header.Height)
			dkgHeight++
		}
		dkgRunner.fastSync = false
	}
	return nil
}

// OnStart overrides BaseService. Starts first DKG.
func (dkgRunner *DKGRunner) OnStart() error {
	dkgRunner.checkNextDKG()
	return nil
}

// OnBlock is callback in messageHandler for DKG messages included in a particular block
func (dkgRunner *DKGRunner) OnBlock(blockHeight int64, entropy types.ThresholdSignature, trxs []*types.DKGMessage) {
	dkgRunner.mtx.Lock()
	dkgRunner.metrics.DKGMessagesInChain.Add(float64(len(trxs)))

	if len(entropy) != 0 && blockHeight > dkgRunner.aeonEnd {
		// DKG should not be stale
		panic(fmt.Errorf("Unexpected entropy in block %v, aeon end %v", blockHeight, dkgRunner.aeonEnd))
	} else if dkgRunner.activeDKG != nil {
		dkgRunner.mtx.Unlock()
		dkgRunner.activeDKG.OnBlock(blockHeight, trxs)
		dkgRunner.mtx.Lock()
	}

	if !dkgRunner.fastSync {
		dkgRunner.height = blockHeight
		dkgRunner.checkNextDKG()
	}

	dkgRunner.mtx.Unlock()
}

// Returns validators for height from state DB
func (dkgRunner *DKGRunner) findValidatorsAndParams(height int64) (*types.ValidatorSet, int64) {
	for {
		if !dkgRunner.fastSync && !dkgRunner.IsRunning() {
			dkgRunner.Logger.Debug("findValidators: exiting", "height", dkgRunner.height)
			return nil, 0
		}

		newVals, err := sm.LoadValidators(dkgRunner.stateDB, height)
		newParams, err1 := sm.LoadConsensusParams(dkgRunner.stateDB, height)
		if err != nil || err1 != nil {
			time.Sleep(100 * time.Millisecond)
		} else {
			dkgRunner.Logger.Debug("findValidators: vals updated", "height", height)
			return newVals, newParams.Entropy.AeonLength
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
		vals, aeonLength := dkgRunner.findValidatorsAndParams(validatorHeight)
		if vals == nil {
			// Should only return nil if dkg runner is stopped and not in fast sync
			dkgRunner.Logger.Debug("findValidatorsAndParams return nil vals", "fastSync",
				dkgRunner.fastSync, "dkgRunner running", dkgRunner.IsRunning())
			return
		}
		dkgRunner.startNewDKG(validatorHeight, vals, aeonLength)
	}
}

// Starts new DKG if old one has completed for those in the current validator set
func (dkgRunner *DKGRunner) startNewDKG(validatorHeight int64, validators *types.ValidatorSet, aeonLength int64) {
	dkgRunner.Logger.Debug("startNewDKG: successful", "height", validatorHeight)
	// Create new dkg that starts DKGResetDelay after most recent block height
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.consensusConfig, dkgRunner.chainID,
		dkgRunner.privVal, dkgRunner.encryptionKey, validatorHeight, *validators, dkgRunner.aeonEnd, aeonLength)
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
		dkgRunner.metrics.DKGsCompleted.Add(1)
		if keys.aeonExecUnit.CanSign() {
			dkgRunner.metrics.DKGsCompletedWithPrivateKey.Add(1)
		}
		dkgRunner.SetCurrentAeon(keys.Start, keys.End)
		if dkgRunner.dkgCompletionCallback != nil {
			dkgRunner.dkgCompletionCallback(keys)
		}
	})
	dkgRunner.activeDKG.attachMetrics(dkgRunner.metrics)
}
