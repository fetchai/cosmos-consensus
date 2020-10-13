package beacon

import (
	"fmt"
	"sync"
	"time"

	"github.com/flynn/noise"
	dbm "github.com/tendermint/tm-db"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/service"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
)

const (
	maxFindValSleepIterations = 10 // Equal to 1s total sleep time
	findValSleepDuration      = 100 * time.Millisecond
)

// DKGRunner manages the starting of the DKG each aeon with new validator sets and forwards on
// the output of the DKG. New DKGs are started at the beginning of every aeon assuming the previous
// DKG completed on time.
type DKGRunner struct {
	service.BaseService
	beaconConfig   *cfg.BeaconConfig
	chainID        string
	stateDB        dbm.DB
	privVal        types.PrivValidator
	messageHandler tx_extensions.MessageHandler

	height       int64
	aeonStart    int64 // next entropy generation start
	aeonEnd      int64 // next entropy generation end
	validators   types.ValidatorSet
	activeDKG    *DistributedKeyGeneration
	completedDKG bool
	dkgID        int64

	dkgCompletionCallback func(aeon *aeonDetails)
	fastSync              bool

	encryptionKey        noise.DHKey
	slotProtocolEnforcer *SlotProtocolEnforcer

	mtx     sync.Mutex
	metrics *Metrics

	evpool evidencePool
}

// NewDKGRunner creates struct for starting new DKGs
func NewDKGRunner(config *cfg.BeaconConfig, chain string, db dbm.DB, val types.PrivValidator,
	encryptionKey noise.DHKey, blockHeight int64, slotProtocolEnforcer *SlotProtocolEnforcer, evpool evidencePool) *DKGRunner {
	dkgRunner := &DKGRunner{
		beaconConfig:         config,
		chainID:              chain,
		stateDB:              db,
		privVal:              val,
		height:               blockHeight,
		aeonStart:            -1,
		aeonEnd:              -1,
		completedDKG:         false,
		dkgID:                -1,
		metrics:              NopMetrics(),
		fastSync:             false,
		encryptionKey:        encryptionKey,
		slotProtocolEnforcer: slotProtocolEnforcer,
		evpool:               evpool,
	}
	dkgRunner.BaseService = *service.NewBaseService(nil, "DKGRunner", dkgRunner)

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

// SetCurrentAeon sets the lastest aeon in the key files
func (dkgRunner *DKGRunner) SetCurrentAeon(aeon *aeonDetails) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if aeon == nil {
		return
	}
	if aeon.IsKeyless() {
		// aeonStart is fetched from dkgRunner to be included in the  block and must
		// always correspond to the start of entropy generation periods, or -1
		dkgRunner.aeonStart = aeon.validatorHeight
		// Special case for genesis.
		if dkgRunner.aeonStart == 1 {
			dkgRunner.aeonStart = -1
		}
	} else {
		dkgRunner.aeonStart = aeon.Start
	}
	dkgRunner.aeonEnd = aeon.End
	dkgRunner.dkgID = aeon.dkgID
}

// setNextAeon sets the new aeon from dkg completion
func (dkgRunner *DKGRunner) setNextAeon(aeon *aeonDetails) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if aeon.IsKeyless() {
		return
	}
	dkgRunner.aeonStart = aeon.Start
	dkgRunner.aeonEnd = aeon.End
	dkgRunner.dkgID = aeon.dkgID
}

// FastSync runs a dkg from block messages up to current block height
// for catch up
func (dkgRunner *DKGRunner) FastSync(blockStore sm.BlockStore) error {
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
		for dkgRunner.height >= dkgHeight {
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
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
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

// NextAeonStart returns the start of the next entropy generation aeon
func (dkgRunner *DKGRunner) NextAeonStart(height int64) int64 {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if height != dkgRunner.height+1 {
		panic(fmt.Sprintf("consensus state requested next aeon start for unexpected height %v. Expected %v", height, dkgRunner.height+1))
	}
	return dkgRunner.aeonStart
}

// Returns validators for height from state DB
func (dkgRunner *DKGRunner) findValidatorsAndParams(height int64) (*types.ValidatorSet, types.EntropyParams) {
	sleepIterations := 0
	for {
		if !dkgRunner.fastSync && !dkgRunner.IsRunning() {
			dkgRunner.Logger.Debug("findValidators: exiting", "height", dkgRunner.height)
			return nil, types.EntropyParams{}
		}
		if sleepIterations > maxFindValSleepIterations {
			panic(fmt.Sprintf("findValidatorsAndParams: could not retrieve for height %v", height))
		}

		newVals, err := sm.LoadDKGValidators(dkgRunner.stateDB, height)
		newParams, err1 := sm.LoadConsensusParams(dkgRunner.stateDB, height)
		if err != nil || err1 != nil {
			sleepIterations++
			time.Sleep(findValSleepDuration)
		} else {
			if newVals.Size() == 0 {
				panic(fmt.Sprintf("findValidators returned empty validator set. Height %v", height))
			}
			dkgRunner.Logger.Debug("findValidators: vals updated", "height", height)
			return newVals, newParams.Entropy
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
func (dkgRunner *DKGRunner) startNewDKG(validatorHeight int64, validators *types.ValidatorSet, entropyParams types.EntropyParams) {
	dkgRunner.Logger.Debug("startNewDKG: successful", "height", validatorHeight)
	dkgRunner.dkgID++

	// Create new dkg that starts DKGResetDelay after most recent block height
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.beaconConfig, dkgRunner.chainID,
		dkgRunner.privVal, dkgRunner.encryptionKey, validatorHeight, dkgRunner.dkgID, *validators, dkgRunner.aeonEnd, entropyParams, dkgRunner.slotProtocolEnforcer)

	// Set logger with dkgID and node index for debugging
	dkgLogger := dkgRunner.Logger.With("dkgID", dkgRunner.activeDKG.dkgID, "iteration", dkgRunner.activeDKG.dkgIteration,
		"index", dkgRunner.activeDKG.index())
	dkgRunner.activeDKG.SetLogger(dkgLogger)

	// Set message handler for sending DKG transactions
	dkgRunner.activeDKG.SetSendMsgCallback(func(msg *types.DKGMessage) {
		dkgRunner.messageHandler.SubmitSpecialTx(msg)
	})
	// Mark dkg completion so so that activeDKG can be reset and set start and end
	// of next entropy aeon
	dkgRunner.activeDKG.SetDkgCompletionCallback(func(keys *aeonDetails) {
		if keys.aeonExecUnit != nil {
			dkgRunner.completedDKG = true
			dkgRunner.metrics.DKGsCompleted.Add(1)
			if keys.aeonExecUnit.CanSign() {
				dkgRunner.metrics.DKGsCompletedWithPrivateKey.Add(1)
			}
			dkgRunner.setNextAeon(keys)
		}
		if dkgRunner.dkgCompletionCallback != nil {
			dkgRunner.dkgCompletionCallback(keys)
		}
	})
	// Set evidence handler
	dkgRunner.activeDKG.evidenceHandler = func(ev *types.DKGEvidence) {
		err := dkgRunner.evpool.AddEvidence(ev)
		if err != nil {
			dkgRunner.Logger.Error("Error adding dkg evidence", "err", err)
		}
	}
	// Dispatch off empty keys in case entropy generator has no keys. Keyless offset is required for
	// app to have sufficient notification time of new aeon start
	if dkgRunner.dkgCompletionCallback != nil {
		dkgRunner.dkgCompletionCallback(keylessAeonDetails(dkgRunner.activeDKG.dkgID, validatorHeight,
			dkgRunner.activeDKG.startHeight, dkgRunner.activeDKG.startHeight+
				dkgRunner.activeDKG.duration()+keylessOffset))
	}

	dkgRunner.activeDKG.attachMetrics(dkgRunner.metrics)
}
