package beacon

import (
	"fmt"
	"sync"
	"time"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto/tmhash"
	cmn "github.com/tendermint/tendermint/libs/common"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/libs/log"

	//"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

const (
	// History length of entropy to keep in number of blocks
	entropyHistoryLength = 10
)

// EntropyGenerator holds DKG keys for computing entropy and computes entropy shares
// and entropy for dispatching along channel
type EntropyGenerator struct {
	cmn.BaseService

	mtx sync.RWMutex

	entropyShares             map[int64]map[uint]types.EntropyShare
	entropyComputed           map[int64]types.ThresholdSignature
	lastBlockHeight           int64 // last block height
	lastComputedEntropyHeight int64 // last non-trivial entropy

	// Channel for sending off entropy for receiving elsewhere
	computedEntropyChannel chan<- types.ComputedEntropy
	nextAeon               *aeonDetails
	aeon                   *aeonDetails

	baseConfig      *cfg.BaseConfig
	consensusConfig *cfg.ConsensusConfig

	// synchronous pubsub between entropy generator and reactor.
	// entropy generator only emits new computed entropy height
	evsw tmevents.EventSwitch

	// closed when shutting down to unblock send to full channel
	quit chan struct{}
	// closed when we finish shutting down
	done chan struct{}
}

// NewEntropyGenerator creates new entropy generator with validator information
func NewEntropyGenerator(bConfig *cfg.BaseConfig, csConfig *cfg.ConsensusConfig, blockHeight int64) *EntropyGenerator {
	if bConfig == nil || csConfig == nil {
		panic(fmt.Errorf("NewEntropyGenerator: baseConfig/consensusConfig can not be nil"))
	}
	es := &EntropyGenerator{
		entropyShares:             make(map[int64]map[uint]types.EntropyShare),
		lastBlockHeight:           blockHeight,
		lastComputedEntropyHeight: -1, // value is invalid and requires last entropy to be set
		entropyComputed:           make(map[int64]types.ThresholdSignature),
		baseConfig:                bConfig,
		consensusConfig:           csConfig,
		evsw:                      tmevents.NewEventSwitch(),
		quit:                      make(chan struct{}),
		done:                      make(chan struct{}),
	}

	es.BaseService = *cmn.NewBaseService(nil, "EntropyGenerator", es)
	return es
}

// OnStart generates entropy from the last computed entropy height
func (entropyGenerator *EntropyGenerator) OnStart() error {
	if err := entropyGenerator.evsw.Start(); err != nil {
		entropyGenerator.Logger.Error("OnStart: failed to start event switch")
		return err
	}

	entropyGenerator.Logger.Debug("OnStart", "height", entropyGenerator.lastBlockHeight,
		"aeon", entropyGenerator.isSigningEntropy(), "lastEntropyHeight", entropyGenerator.lastComputedEntropyHeight)

	if entropyGenerator.lastComputedEntropyHeight > -1 {
		// Notify peers of starting entropy
		entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastComputedEntropyHeight)
		// Sign entropy
		entropyGenerator.sign()
	}

	// Start go routine for computing threshold signature
	go entropyGenerator.computeEntropyRoutine()
	return nil
}

// OnStop stops event switch
func (entropyGenerator *EntropyGenerator) OnStop() {
	entropyGenerator.evsw.Stop()
	close(entropyGenerator.quit)
}

// Wait waits for the computeEntropyRoutine to return.
func (entropyGenerator *EntropyGenerator) wait() {
	// Try to stop gracefully by waiting for routine to return
	t := time.NewTimer(2 * entropyGenerator.consensusConfig.ComputeEntropySleepDuration)
	select {
	case <-t.C:
		panic(fmt.Errorf("wait timeout - deadlock in closing channel"))
	case <-entropyGenerator.done:
	}
}

// SetComputedEntropyChannel sets the channel along which entropy should be dispatched
func (entropyGenerator *EntropyGenerator) SetComputedEntropyChannel(entropyChannel chan<- types.ComputedEntropy) {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	if entropyGenerator.computedEntropyChannel == nil {
		entropyGenerator.computedEntropyChannel = entropyChannel
	}
}

// SetLogger implements Service.
func (entropyGenerator *EntropyGenerator) SetLogger(l log.Logger) {
	entropyGenerator.BaseService.Logger = l
}

// SetAeonDetails sets the DKG keys for computing DRB (used on creation of NewNode)
func (entropyGenerator *EntropyGenerator) SetAeonDetails(aeon *aeonDetails) {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	// Check entropy keys are not old
	if entropyGenerator.lastBlockHeight+1 > aeon.End {
		return
	}
	entropyGenerator.aeon = aeon
}

// SetLastComputedEntropy sets the most recent entropy from catchup
func (entropyGenerator *EntropyGenerator) SetLastComputedEntropy(entropy types.ComputedEntropy) {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	if entropyGenerator.entropyComputed[entropy.Height] != nil {
		entropyGenerator.Logger.Error("Attempt to reset existing entropy", "height", entropy.Height)
		return
	}
	entropyGenerator.entropyComputed[entropy.Height] = entropy.GroupSignature
	// If new entropy is more recent that our last computed entropy then update
	if entropy.Height > entropyGenerator.lastComputedEntropyHeight {
		entropyGenerator.lastComputedEntropyHeight = entropy.Height
	}
}

func (entropyGenerator *EntropyGenerator) setLastBlockHeight(height int64) {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	if height > entropyGenerator.lastBlockHeight {
		entropyGenerator.lastBlockHeight = height
	}
}

// SetNextAeonDetails adds new AeonDetails from DKG into the queue
func (entropyGenerator *EntropyGenerator) SetNextAeonDetails(aeon *aeonDetails) {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	// Check no existing nextAeon
	if entropyGenerator.nextAeon != nil {
		panic(fmt.Errorf("SetNextAeonDetails: Overwriting existing next aeon. Existing aeon start %v, new aeon start %v",
			entropyGenerator.nextAeon.Start, aeon.Start))
	}
	// Check entropy keys are not old
	if entropyGenerator.lastBlockHeight+1 > aeon.End {
		return
	}
	// Check start and ends are compatible
	if entropyGenerator.aeon != nil {
		if aeon.Start <= entropyGenerator.aeon.End {
			entropyGenerator.Logger.Error("SetNextAeonDetails: incompatible new aeon received", "new aeon start", aeon.Start,
				"existing aeon end", entropyGenerator.aeon.End)
			return
		}
	}
	entropyGenerator.nextAeon = aeon
	// Save keys for crash recovery
	entropyGenerator.nextAeon.save(entropyGenerator.baseConfig.NextEntropyKeyFile())
	entropyGenerator.Logger.Debug("SetNextAeonDetails: next aeon received", "start", aeon.Start, "end", aeon.End)
}

func (entropyGenerator *EntropyGenerator) changeKeys() bool {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	// Reset aeon to nil at the end of its time
	if entropyGenerator.aeon != nil && entropyGenerator.lastBlockHeight+1 > entropyGenerator.aeon.End {
		entropyGenerator.Logger.Debug("changeKeys: Existing keys expired. Resetting.", "blockHeight", entropyGenerator.lastBlockHeight,
			"end", entropyGenerator.aeon.End)
		entropyGenerator.aeon = nil
	}

	if entropyGenerator.nextAeon != nil {
		if entropyGenerator.lastBlockHeight+1 < entropyGenerator.nextAeon.Start {
			entropyGenerator.Logger.Debug("changeKeys: Found keys not yet ready", "blockHeight", entropyGenerator.lastBlockHeight,
				"start", entropyGenerator.nextAeon.Start)
			return false
		}
		entropyGenerator.aeon = entropyGenerator.nextAeon
		entropyGenerator.nextAeon = nil
		// Save keys for crash recovery
		entropyGenerator.aeon.save(entropyGenerator.baseConfig.EntropyKeyFile())

		// If lastComputedEntropyHeight is not set then set it is equal to group public key (should
		// only be the case one for first DKG after genesis)
		if entropyGenerator.lastComputedEntropyHeight == -1 {
			entropyGenerator.lastComputedEntropyHeight = entropyGenerator.lastBlockHeight
			entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight] =
				[]byte(entropyGenerator.aeon.aeonExecUnit.GroupPublicKey())
		}
		entropyGenerator.Logger.Debug("changeKeys: Loaded new keys", "blockHeight", entropyGenerator.lastBlockHeight,
			"start", entropyGenerator.aeon.Start)
		return true
	}
	entropyGenerator.Logger.Debug("changeKeys: No new keys", "blockHeight", entropyGenerator.lastBlockHeight)
	return false
}

// ApplyComputedEntropy processes completed entropy from peer
func (entropyGenerator *EntropyGenerator) applyComputedEntropy(entropy *types.ComputedEntropy) {
	// Should not be called in entropy generator is not running
	if !entropyGenerator.isSigningEntropy() {
		panic(fmt.Errorf("applyEntropyShare while entropy generator stopped"))
	}
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	entropyGenerator.Logger.Debug("applyComputedEntropy", "height", entropy.Height)

	// Only process if corresponds to next entropy
	if entropyGenerator.entropyComputed[entropy.Height] == nil && entropy.Height == entropyGenerator.lastBlockHeight+1 {
		message := string(tmhash.Sum(entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight]))
		if entropyGenerator.aeon.aeonExecUnit.VerifyGroupSignature(message, string(entropy.GroupSignature)) {
			entropyGenerator.entropyComputed[entropy.Height] = entropy.GroupSignature
		} else {
			entropyGenerator.Logger.Error("received invalid computed entropy")
		}
	}
	//TODO: Should down rate peers which send irrelevant computed entropy or invalid entropy
}

// ApplyEntropyShare processes entropy share from reactor
func (entropyGenerator *EntropyGenerator) applyEntropyShare(share *types.EntropyShare) {
	// Should not be called in entropy generator is not running
	if !entropyGenerator.isSigningEntropy() {
		panic(fmt.Errorf("applyEntropyShare while entropy generator stopped"))
	}

	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	entropyGenerator.Logger.Debug("applyEntropyShare", "height", share.Height, "from", share.SignerAddress)
	index, validator := entropyGenerator.aeon.validators.GetByAddress(share.SignerAddress)
	err := entropyGenerator.validInputs(share.Height, index)
	if err != nil {
		entropyGenerator.Logger.Debug("applyEntropyShare: rejected share", "error", err.Error())
		return
	}

	// Verify signature on message
	verifySig := validator.PubKey.VerifyBytes(share.SignBytes(entropyGenerator.baseConfig.ChainID()), share.Signature)
	if !verifySig {
		entropyGenerator.Logger.Error("applyEntropyShare: invalid validator signature", "validator", share.SignerAddress, "index", index)
		return
	}

	// Verify share
	message := string(tmhash.Sum(entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight]))
	if !entropyGenerator.aeon.aeonExecUnit.Verify(message, share.SignatureShare, uint(index)) {
		entropyGenerator.Logger.Error("applyEntropyShare: invalid entropy share", "validator", share.SignerAddress, "index", index)
		return
	}

	entropyGenerator.Logger.Debug("applyEntropyShare: valid share received", "height", share.Height, "validator index", index)
	if entropyGenerator.entropyShares[share.Height] == nil {
		entropyGenerator.entropyShares[share.Height] = make(map[uint]types.EntropyShare)
	}

	entropyGenerator.entropyShares[share.Height][uint(index)] = share.Copy()
	return
}

func (entropyGenerator *EntropyGenerator) getLastComputedEntropyHeight() int64 {
	entropyGenerator.mtx.RLock()
	defer entropyGenerator.mtx.RUnlock()

	return entropyGenerator.lastComputedEntropyHeight
}

func (entropyGenerator *EntropyGenerator) getLastBlockHeight() int64 {
	entropyGenerator.mtx.RLock()
	defer entropyGenerator.mtx.RUnlock()

	return entropyGenerator.lastBlockHeight
}

func (entropyGenerator *EntropyGenerator) getComputedEntropy(height int64) types.ThresholdSignature {
	entropyGenerator.mtx.RLock()
	defer entropyGenerator.mtx.RUnlock()

	return entropyGenerator.entropyComputed[height]
}

// GetEntropyShares gets entropy shares at a particular height
func (entropyGenerator *EntropyGenerator) getEntropyShares(height int64) map[uint]types.EntropyShare {
	entropyGenerator.mtx.RLock()
	defer entropyGenerator.mtx.RUnlock()
	sharesCopy := make(map[uint]types.EntropyShare)
	for key, share := range entropyGenerator.entropyShares[height] {
		sharesCopy[key] = share.Copy()
	}
	return sharesCopy
}

func (entropyGenerator *EntropyGenerator) validInputs(height int64, index int) error {
	if index < 0 {
		return fmt.Errorf("invalid validator index %v", index)
	}
	if height <= entropyGenerator.lastBlockHeight {
		return fmt.Errorf("already computed entropy at height %v", height)
	}
	if height > entropyGenerator.lastBlockHeight+1 {
		return fmt.Errorf("missing previous entropy at height %v", height-1)
	}
	if len(entropyGenerator.entropyShares[height][uint(index)].SignatureShare) != 0 {
		return fmt.Errorf("already have entropy share at height %v index %v", height, index)
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign() {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	if entropyGenerator.aeon == nil || !entropyGenerator.aeon.aeonExecUnit.CanSign() {
		entropyGenerator.Logger.Debug("sign: no dkg private key", "height", entropyGenerator.lastBlockHeight+1)
		return
	}
	index, _ := entropyGenerator.aeon.validators.GetByAddress(entropyGenerator.aeon.privValidator.GetPubKey().Address())
	blockHeight := entropyGenerator.lastBlockHeight + 1
	err := entropyGenerator.validInputs(blockHeight, index)
	if err != nil {
		entropyGenerator.Logger.Debug(err.Error())
		return
	}
	entropyGenerator.Logger.Debug("sign: block entropy", "blockHeight", blockHeight, "lastEentropyHeight", entropyGenerator.lastComputedEntropyHeight,
		"nodeAddress", entropyGenerator.aeon.privValidator.GetPubKey().Address())

	message := string(tmhash.Sum(entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight]))
	signature := entropyGenerator.aeon.aeonExecUnit.Sign(message)

	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[blockHeight] == nil {
		entropyGenerator.entropyShares[blockHeight] = make(map[uint]types.EntropyShare)
	}
	share := types.EntropyShare{
		Height:         blockHeight,
		SignerAddress:  entropyGenerator.aeon.privValidator.GetPubKey().Address(),
		SignatureShare: signature,
	}
	// Sign message
	err = entropyGenerator.aeon.privValidator.SignEntropy(entropyGenerator.baseConfig.ChainID(), &share)
	if err != nil {
		entropyGenerator.Logger.Error(err.Error())
		return
	}
	entropyGenerator.entropyShares[blockHeight][uint(index)] = share
}

// OnBlock form pubsub that updates last block height
// While aeon = nil have checkTransition on nextAeon (no computeEntropyRoutine running)
// While aeon != nil start computeEntropyRoutine

func (entropyGenerator *EntropyGenerator) computeEntropyRoutine() {
	onExit := func(entropyGenerator *EntropyGenerator) {
		entropyGenerator.Logger.Info("computedEntropyRoutine exiting")
		if entropyGenerator.computedEntropyChannel != nil {
			close(entropyGenerator.computedEntropyChannel)
		}
		close(entropyGenerator.done)
	}

	for {

		// Close channel and exit go routine if entropy generator is not running
		if !entropyGenerator.IsRunning() {
			onExit(entropyGenerator)
			return
		}

		haveNewEntropy, entropyToSend := entropyGenerator.checkForNewEntropy()
		if haveNewEntropy {
			// Need to unlock before dispatching to entropy channel otherwise deadlocks
			// Note: safe to access lastComputeEntropyHeight without lock here as it is only
			// modified within this go routine.
			// Select is present to allow closing of channel on stopping if stuck on send
			if entropyGenerator.computedEntropyChannel != nil {
				select {
				case entropyGenerator.computedEntropyChannel <- *entropyToSend:
				case <-entropyGenerator.quit:
					onExit(entropyGenerator)
					return
				}

			}
			// Check whether we should change keys
			entropyGenerator.changeKeys()
			// Continue onto the next random value
			entropyGenerator.sign()
			// Clean out old entropy shares and computed entropy
			entropyGenerator.flushOldEntropy()
		}
		time.Sleep(entropyGenerator.consensusConfig.ComputeEntropySleepDuration)
	}
}

func (entropyGenerator *EntropyGenerator) checkForNewEntropy() (bool, *types.ComputedEntropy) {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	height := entropyGenerator.lastBlockHeight + 1
	if entropyGenerator.aeon == nil {
		entropyGenerator.lastBlockHeight++
		entropyGenerator.Logger.Debug("checkForNewEntropy: trivial entropy", "height", entropyGenerator.lastBlockHeight)
		entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastBlockHeight)
		return true, types.NewComputedEntropy(height, nil, false)
	}

	if entropyGenerator.entropyComputed[height] != nil {
		entropyGenerator.Logger.Info("New entropy computed", "height", height)
		entropyGenerator.lastBlockHeight++
		entropyGenerator.lastComputedEntropyHeight = entropyGenerator.lastBlockHeight

		// Notify peers of of new entropy height
		entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastComputedEntropyHeight)
		return true, types.NewComputedEntropy(height, entropyGenerator.entropyComputed[height], true)
	}
	if len(entropyGenerator.entropyShares[height]) >= entropyGenerator.aeon.threshold {
		message := string(tmhash.Sum(entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight]))
		signatureShares := NewIntStringMap()
		defer DeleteIntStringMap(signatureShares)

		for key, share := range entropyGenerator.entropyShares[height] {
			signatureShares.Set(key, share.SignatureShare)
		}
		groupSignature := entropyGenerator.aeon.aeonExecUnit.ComputeGroupSignature(signatureShares)
		if !entropyGenerator.aeon.aeonExecUnit.VerifyGroupSignature(message, groupSignature) {
			entropyGenerator.Logger.Error("entropy_generator.VerifyGroupSignature == false")
			return false, nil
		}
		entropyGenerator.Logger.Info("New entropy computed", "height", height)
		entropyGenerator.entropyComputed[height] = []byte(groupSignature)
		entropyGenerator.lastBlockHeight++
		entropyGenerator.lastComputedEntropyHeight = entropyGenerator.lastBlockHeight

		// Notify peers of of new entropy height
		entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastComputedEntropyHeight)
		return true, types.NewComputedEntropy(height, entropyGenerator.entropyComputed[height], true)
	}
	return false, nil
}

func (entropyGenerator *EntropyGenerator) flushOldEntropy() {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	deleteHeight := entropyGenerator.lastComputedEntropyHeight - entropyHistoryLength
	if deleteHeight >= 0 {
		// Clean entropy shares
		delete(entropyGenerator.entropyShares, deleteHeight)
		// Clean computed entropy
		delete(entropyGenerator.entropyComputed, deleteHeight)
	}
}

func (entropyGenerator *EntropyGenerator) isSigningEntropy() bool {
	entropyGenerator.mtx.Lock()
	defer entropyGenerator.mtx.Unlock()

	return entropyGenerator.aeon != nil
}
