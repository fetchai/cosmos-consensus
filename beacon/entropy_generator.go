package beacon

import (
	"fmt"
	"sync"
	"time"

	"github.com/tendermint/tendermint/crypto/tmhash"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

var (
	// EntropyChannelCapacity is number of ComputedEntropy that channel can hold
	EntropyChannelCapacity = 3
)

// EntropyGenerator holds DKG keys for computing entropy and computes entropy shares
// and entropy for dispatching along channel
type EntropyGenerator struct {
	service.BaseService

	proxyMtx sync.Mutex

	threshold                 int
	entropyShares             map[int64]map[int]types.EntropyShare
	entropyComputed           map[int64]types.ThresholdSignature
	lastComputedEntropyHeight int64

	// Channel for sending off entropy for receiving elsewhere
	computedEntropyChannel chan<- types.ComputedEntropy

	// To be safe, need to store set of validators who can participate in DRB here to avoid
	// possible problems with validator set changing allowed by Tendermint
	privValidator types.PrivValidator
	Validators    *types.ValidatorSet
	aeonExecUnit  AeonExecUnit

	// synchronous pubsub between entropy generator and reactor.
	// entropy generator only emits new computed entropy height
	evsw tmevents.EventSwitch

	// For signing entropy messages
	chainID string

	// closed when shutting down to unblock send to full channel
	quit chan struct{}
	// closed when we finish shutting down
	done chan struct{}
}

// NewEntropyGenerator creates new entropy generator with validator information
func NewEntropyGenerator(
	validators *types.ValidatorSet, newPrivValidator types.PrivValidator, newChainID string) *EntropyGenerator {
	if validators == nil {
		panic(fmt.Sprintf("NewEntropyGenerator with nil validator set"))
	}
	es := &EntropyGenerator{
		entropyShares:             make(map[int64]map[int]types.EntropyShare),
		lastComputedEntropyHeight: -1, // value is invalid and requires last entropy to be set
		entropyComputed:           make(map[int64]types.ThresholdSignature),
		privValidator:             newPrivValidator,
		Validators:                validators,
		evsw:                      tmevents.NewEventSwitch(),
		chainID:                   newChainID,
		quit:                      make(chan struct{}),
		done:                      make(chan struct{}),
	}

	es.threshold = es.Validators.Size()/2 + 1
	es.BaseService = *service.NewBaseService(nil, "EntropyGenerator", es)
	return es
}

// SetLastComputedEntropy sets the most recent entropy from catchup
func (entropyGenerator *EntropyGenerator) SetLastComputedEntropy(entropy types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

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

// SetAeonKeys sets the DKG keys for computing DRB
func (entropyGenerator *EntropyGenerator) SetAeonKeys(aeonKeys AeonExecUnit) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.aeonExecUnit = aeonKeys
}

// SetComputedEntropyChannel sets the channel along which entropy should be dispatched
func (entropyGenerator *EntropyGenerator) SetComputedEntropyChannel(entropyChannel chan<- types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.computedEntropyChannel == nil {
		entropyGenerator.computedEntropyChannel = entropyChannel
	}
}

// SetLogger implements Service.
func (entropyGenerator *EntropyGenerator) SetLogger(l log.Logger) {
	entropyGenerator.BaseService.Logger = l
}

// OnStart generates entropy from the last computed entropy height
func (entropyGenerator *EntropyGenerator) OnStart() error {
	if entropyGenerator.aeonExecUnit == nil {
		panic(fmt.Errorf("OnStart with no active execution unit"))
	}

	if entropyGenerator.lastComputedEntropyHeight < types.GenesisHeight {
		panic(fmt.Sprintf("OnStart without setting last computed entropy"))
	}

	if err := entropyGenerator.evsw.Start(); err != nil {
		entropyGenerator.Logger.Error("EntropyGenerator failed to start event switch")
		return err
	}

	// Notify peers of starting entropy
	entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastComputedEntropyHeight)

	entropyGenerator.Logger.Info("EntropyGenerator start", "height", entropyGenerator.lastComputedEntropyHeight)
	// Sign entropy
	entropyGenerator.sign(entropyGenerator.lastComputedEntropyHeight)

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
	t := time.NewTimer(2 * computeEntropySleepDuration)
	select {
	case <-t.C:
		panic(fmt.Errorf("wait timeout - deadlock in closing channel"))
	case <-entropyGenerator.done:
	}
}

func (entropyGenerator *EntropyGenerator) getLastComputedEntropyHeight() int64 {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	return entropyGenerator.lastComputedEntropyHeight
}

func (entropyGenerator *EntropyGenerator) getComputedEntropy(height int64) types.ThresholdSignature {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	return entropyGenerator.entropyComputed[height]
}

// ApplyComputedEntropy processes completed entropy from peer
func (entropyGenerator *EntropyGenerator) applyComputedEntropy(entropy *types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.Logger.Debug("applyComputedEntropy", "height", entropy.Height)

	// Only process if corresponds to next entropy
	if entropyGenerator.entropyComputed[entropy.Height] == nil && entropy.Height == entropyGenerator.lastComputedEntropyHeight+1 {
		message := string(tmhash.Sum(entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight]))
		if entropyGenerator.aeonExecUnit.VerifyGroupSignature(message, string(entropy.GroupSignature)) {
			entropyGenerator.entropyComputed[entropy.Height] = entropy.GroupSignature
		} else {
			entropyGenerator.Logger.Error("received invalid computed entropy")
		}
	}
	//TODO: Should down rate peers which send irrelevant computed entropy or invalid entropy
}

// ApplyEntropyShare processes entropy share from reactor
func (entropyGenerator *EntropyGenerator) applyEntropyShare(share *types.EntropyShare) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.Logger.Debug("applyEntropyShare", "height", share.Height, "from", share.SignerAddress)
	index, validator := entropyGenerator.Validators.GetByAddress(share.SignerAddress)
	err := entropyGenerator.validInputs(share.Height, index)
	if err != nil {
		entropyGenerator.Logger.Debug("applyEntropyShare invalid share", "error", err.Error())
		return
	}

	// Verify signature on message
	verifySig := validator.PubKey.VerifyBytes(share.SignBytes(entropyGenerator.chainID), share.Signature)
	if !verifySig {
		entropyGenerator.Logger.Error("invalid validator signature on entropy share", "validator", share.SignerAddress, "index", index)
		return
	}

	// Verify share
	message := string(tmhash.Sum(entropyGenerator.entropyComputed[share.Height-1]))
	if !entropyGenerator.aeonExecUnit.Verify(message, share.SignatureShare, uint64(index)) {
		entropyGenerator.Logger.Error("invalid entropy share", "validator", share.SignerAddress, "index", index)
		return
	}

	entropyGenerator.Logger.Info("New entropy share received", "height", share.Height, "validator index", index)
	if entropyGenerator.entropyShares[share.Height] == nil {
		entropyGenerator.entropyShares[share.Height] = make(map[int]types.EntropyShare)
	}

	entropyGenerator.entropyShares[share.Height][index] = share.Copy()
	return
}

// GetEntropyShares gets entropy shares at a particular height
func (entropyGenerator *EntropyGenerator) getEntropyShares(height int64) map[int]types.EntropyShare {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()
	sharesCopy := make(map[int]types.EntropyShare)
	for key, share := range entropyGenerator.entropyShares[height] {
		sharesCopy[key] = share.Copy()
	}
	return sharesCopy
}

func (entropyGenerator *EntropyGenerator) validInputs(height int64, index int) error {
	if index < 0 {
		return fmt.Errorf("invalid validator index %v", index)
	}
	if height <= entropyGenerator.lastComputedEntropyHeight {
		return fmt.Errorf("already computed entropy at height %v", height)
	}
	if height > entropyGenerator.lastComputedEntropyHeight+1 {
		return fmt.Errorf("missing previous entropy at height %v", height-1)
	}
	if len(entropyGenerator.entropyShares[height][index].SignatureShare) != 0 {
		return fmt.Errorf("already have entropy share at height %v index %v", height, index)
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign(height int64) {
	if !entropyGenerator.aeonExecUnit.CanSign() {
		entropyGenerator.Logger.Debug("node can not sign entropy - no dkg private key")
		return
	}
	// Node which can sign on entropy should also be a validator
	if entropyGenerator.privValidator == nil {
		panic(fmt.Sprintf("entropy generator with invalid privValidator"))
	}
	index, _ := entropyGenerator.Validators.GetByAddress(entropyGenerator.privValidator.GetPubKey().Address())
	err := entropyGenerator.validInputs(height+1, index)
	if err != nil {
		if index < 0 {
			panic(fmt.Sprintf("entropy generator with invalid privValidator"))
		}
		entropyGenerator.Logger.Debug(err.Error())
		return
	}

	entropyGenerator.Logger.Debug("sign block entropy", "height", height, "nodeAddress", entropyGenerator.privValidator.GetPubKey().Address())

	message := string(tmhash.Sum(entropyGenerator.entropyComputed[height]))
	signature := entropyGenerator.aeonExecUnit.Sign(message)
	if !entropyGenerator.aeonExecUnit.Verify(message, signature, uint64(index)) {
		entropyGenerator.Logger.Error("sign on block entropy generated invalid signature", "height", height)
		return
	}

	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[height+1] == nil {
		entropyGenerator.entropyShares[height+1] = make(map[int]types.EntropyShare)
	}
	share := types.EntropyShare{
		Height:         height + 1,
		SignerAddress:  entropyGenerator.privValidator.GetPubKey().Address(),
		SignatureShare: signature,
	}
	// Sign message
	err = entropyGenerator.privValidator.SignEntropy(entropyGenerator.chainID, &share)
	if err != nil {
		entropyGenerator.Logger.Error(err.Error())
		return
	}
	entropyGenerator.entropyShares[height+1][index] = share
}

func (entropyGenerator *EntropyGenerator) computeEntropyRoutine() {
	onExit := func(entropyGenerator *EntropyGenerator) {
		entropyGenerator.Logger.Info("computedEntropyRoutine exitting")
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

		entropyGenerator.proxyMtx.Lock()
		haveNewEntropy := entropyGenerator.receivedEntropyShare()
		entropyGenerator.proxyMtx.Unlock()

		if haveNewEntropy {
			// Need to unlock before dispatching to entropy channel otherwise deadlocks
			// Note: safe to access lastComputeEntropyHeight without lock here as it is only
			// modified within this go routine.
			// Select is present to allow closing of channel on stopping if stuck on send
			if entropyGenerator.computedEntropyChannel != nil {
				select {
				case entropyGenerator.computedEntropyChannel <- types.ComputedEntropy{
					Height:         entropyGenerator.lastComputedEntropyHeight,
					GroupSignature: entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight],
				}:
				case <-entropyGenerator.quit:
					onExit(entropyGenerator)
					return
				}

			}

			// Continue onto the next random value
			entropyGenerator.proxyMtx.Lock()
			entropyGenerator.sign(entropyGenerator.lastComputedEntropyHeight)
			entropyGenerator.proxyMtx.Unlock()
		}
		time.Sleep(computeEntropySleepDuration)
	}
}

func (entropyGenerator *EntropyGenerator) receivedEntropyShare() bool {

	height := entropyGenerator.lastComputedEntropyHeight + 1
	if entropyGenerator.entropyComputed[height] != nil {
		entropyGenerator.Logger.Info("New entropy computed", "height", height)
		entropyGenerator.lastComputedEntropyHeight++

		// Notify peers of of new entropy height
		entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastComputedEntropyHeight)

		return true
	}
	if len(entropyGenerator.entropyShares[height]) >= entropyGenerator.threshold {
		message := string(tmhash.Sum(entropyGenerator.entropyComputed[height-1]))
		signatureShares := NewIntStringMap()
		defer DeleteIntStringMap(signatureShares)

		for key, share := range entropyGenerator.entropyShares[height] {
			signatureShares.Set(key, share.SignatureShare)
		}
		groupSignature := entropyGenerator.aeonExecUnit.ComputeGroupSignature(signatureShares)
		if !entropyGenerator.aeonExecUnit.VerifyGroupSignature(message, groupSignature) {
			entropyGenerator.Logger.Error("entropy_generator.VerifyGroupSignature == false")
			return false
		}
		entropyGenerator.Logger.Info("New entropy computed", "height", height)
		entropyGenerator.entropyComputed[height] = []byte(groupSignature)
		entropyGenerator.lastComputedEntropyHeight++

		// Don't delete this yet as need them there for gossiping to peers
		//delete(entropyGenerator.entropyShares, height)

		// Notify peers of of new entropy height
		entropyGenerator.evsw.FireEvent(types.EventComputedEntropy, entropyGenerator.lastComputedEntropyHeight)

		return true
	}
	return false
}
