package beacon

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/tendermint/tendermint/crypto/tmhash"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

var (
	EntropyChannelCapacity = 3
)

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

	// synchronous pubsub between consensus state and reactor.
	// state only emits EventNewRoundStep and EventVote
	evsw tmevents.EventSwitch

	// For signing entropy messages
	chainID string
}

func NewEntropyGenerator(
	validators *types.ValidatorSet, newPrivValidator types.PrivValidator, newChainID string) *EntropyGenerator {
	es := &EntropyGenerator{
		entropyShares:   make(map[int64]map[int]types.EntropyShare),
		entropyComputed: make(map[int64]types.ThresholdSignature),
		privValidator:   newPrivValidator,
		Validators:      validators,
		evsw:            tmevents.NewEventSwitch(),
		chainID:         newChainID,
	}
	es.threshold = es.Validators.Size()/2 + 1
	es.BaseService = *service.NewBaseService(nil, "EntropyGenerator", es)
	return es
}

func (entropyGenerator *EntropyGenerator) SetLastComputedEntropy(entropy types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.entropyComputed[entropy.Height] != nil {
		entropyGenerator.Logger.Error("Attempt to reset existing entropy")
		return
	}
	entropyGenerator.entropyComputed[entropy.Height] = entropy.GroupSignature
}

func (entropyGenerator *EntropyGenerator) SetAeonKeys(aeonKeys AeonExecUnit) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.aeonExecUnit = aeonKeys
}

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

// Generates entropy from the last computed entropy height
func (entropyGenerator *EntropyGenerator) OnStart() error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.aeonExecUnit.Swigcptr() == 0 {
		return fmt.Errorf("no active execution unit")
	}

	// Mark entropy generator as not stopped to allow receiving of messages
	// even if signing fails
	if err := entropyGenerator.evsw.Start(); err != nil {
		return err
	}

	// Find last computed entropy height
	if len(entropyGenerator.entropyComputed) == 0 {
		return fmt.Errorf("no previous entropy to sign")
	}
	entropyHeights := make([]int64, 0, len(entropyGenerator.entropyComputed))
	for height := range entropyGenerator.entropyComputed {
		entropyHeights = append(entropyHeights, height)
	}
	sort.Slice(entropyHeights, func(i int, j int) bool {
		return entropyHeights[i] < entropyHeights[j]
	})
	entropyGenerator.lastComputedEntropyHeight = entropyHeights[len(entropyGenerator.entropyComputed)-1]
	entropyGenerator.sign(entropyGenerator.lastComputedEntropyHeight)
	// Start go routine for computing threshold signature
	go entropyGenerator.computeEntropyRoutine()
	return nil
}

func (entropyGenerator *EntropyGenerator) OnStop() {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.evsw.Stop()
}

func (entropyGenerator *EntropyGenerator) ApplyEntropyShare(share *types.EntropyShare) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.Logger.Debug("ApplyEntropyShare", "height", share.Height, "from", share.SignerAddress)
	index, validator := entropyGenerator.Validators.GetByAddress(share.SignerAddress)
	err := entropyGenerator.validInputs(share.Height, index)
	if err != nil {
		entropyGenerator.Logger.Debug(err.Error())
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

func (entropyGenerator *EntropyGenerator) GetEntropyShares(height int64) map[int]types.EntropyShare {
	return entropyGenerator.entropyShares[height]
}

func (entropyGenerator *EntropyGenerator) validInputs(height int64, index int) error {
	if index < 0 {
		return fmt.Errorf("invalid index %v", index)
	}
	if entropyGenerator.entropyComputed[height] != nil {
		return fmt.Errorf("already computed entropy at height %v", height)
	}
	if entropyGenerator.entropyComputed[height-1] == nil {
		return fmt.Errorf("missing previous entropy at height %v", height-1)
	}
	if len(entropyGenerator.entropyShares[height][index].SignatureShare) != 0 {
		return fmt.Errorf("already have entropy share at height %v index %v", height, index)
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign(height int64) {
	index, _ := entropyGenerator.Validators.GetByAddress(entropyGenerator.privValidator.GetPubKey().Address())
	err := entropyGenerator.validInputs(height+1, index)
	if err != nil {
		entropyGenerator.Logger.Debug(err.Error())
		return
	}
	if !entropyGenerator.aeonExecUnit.CanSign() {
		entropyGenerator.Logger.Error("node can not sign entropy - no dkg private key")
		return
	}
	if entropyGenerator.entropyComputed[height] == nil {
		entropyGenerator.Logger.Error("sign block entropy without previous entropy", "height", height)
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
	entropyGenerator.evsw.FireEvent(types.EventEntropyShare, &share)
}

func (entropyGenerator *EntropyGenerator) computeEntropyRoutine() {
	for {
		entropyGenerator.proxyMtx.Lock()
		haveNewEntropy := entropyGenerator.receivedEntropyShare()
		entropyGenerator.proxyMtx.Unlock()

		if haveNewEntropy {
			// Need to unlock before dispatching to entropy channel otherwise deadlocks
			if entropyGenerator.computedEntropyChannel != nil {
				entropyGenerator.computedEntropyChannel <- types.ComputedEntropy{
					Height:         entropyGenerator.lastComputedEntropyHeight,
					GroupSignature: entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight],
				}
			}

			// Continue onto the next random value
			entropyGenerator.proxyMtx.Lock()
			entropyGenerator.sign(entropyGenerator.lastComputedEntropyHeight)
			entropyGenerator.proxyMtx.Unlock()
		}
		time.Sleep(ComputeEntropySleepDuration)
	}
}

func (entropyGenerator *EntropyGenerator) receivedEntropyShare() bool {

	height := entropyGenerator.lastComputedEntropyHeight + 1
	if entropyGenerator.entropyComputed[height] != nil {
		entropyGenerator.Logger.Error("lastComputedEntropyHeight not updated!")
		entropyGenerator.lastComputedEntropyHeight++
		return false
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

		return true
	}
	return false
}
