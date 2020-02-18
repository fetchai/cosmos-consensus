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
	EntropyChannelCapacity = 5
)

type EntropyGenerator struct {
	service.BaseService

	proxyMtx     sync.Mutex

	threshold int
	entropyShares map[int64]map[int]types.EntropyShare
	entropyComputed map[int64]types.ThresholdSignature
	lastComputedEntropyHeight int64

	// Channel for sending off entropy for receiving elsewhere
	computedEntropyChannel chan<- types.ComputedEntropy

	// To be safe, need to store set of validators who can participate in DRB here to avoid
	// possible problems with validator set changing allowed by Tendermint
	privValidator  types.PrivValidator
	Validators     *types.ValidatorSet
	aeonExecUnit   AeonExecUnit

	// synchronous pubsub between consensus state and reactor.
	// state only emits EventNewRoundStep and EventVote
	evsw tmevents.EventSwitch

	// For signing entropy messages
	chainID string
}

func NewEntropyGenerator(logger log.Logger, validators *types.ValidatorSet, newPrivValidator types.PrivValidator, newChainID string) *EntropyGenerator {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	es := &EntropyGenerator{
		entropyShares: make(map[int64]map[int]types.EntropyShare),
		entropyComputed: make(map[int64]types.ThresholdSignature),
		privValidator: newPrivValidator,
		Validators: validators,
		evsw:             tmevents.NewEventSwitch(),
		chainID: newChainID,
	}
	es.Logger = logger

	es.threshold = es.Validators.Size() / 2 + 1
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
	sort.Slice(entropyHeights, func(i int, j int ) bool {
		return entropyHeights[i] < entropyHeights[j]
	})
	entropyGenerator.lastComputedEntropyHeight = entropyHeights[len(entropyGenerator.entropyComputed) - 1]
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

func (entropyGenerator *EntropyGenerator) ApplyEntropyShare(share *types.EntropyShare) error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	index, validator := entropyGenerator.Validators.GetByAddress(share.SignerAddress)
	err := entropyGenerator.validInputs(share.Height, index)
	if  err != nil {
		return err
	}

	// Verify signature on message
	verifySig := validator.PubKey.VerifyBytes(share.SignBytes(entropyGenerator.chainID), share.Signature)
	if !verifySig {
		return fmt.Errorf("verify of validator signature on entropy share failed")
	}

	// Verify share
	message := string(tmhash.Sum(entropyGenerator.entropyComputed[share.Height - 1]))
	if !entropyGenerator.aeonExecUnit.Verify(message, share.SignatureShare, uint64(index)) {
		return fmt.Errorf("invalid entropy share received from %v", share.SignerAddress)
	}

	entropyGenerator.Logger.Info("New entropy share received", "height", share.Height, "validator index", index)
	if entropyGenerator.entropyShares[share.Height] == nil {
		entropyGenerator.entropyShares[share.Height] = make(map[int]types.EntropyShare)
	}
	newShare := types.EntropyShare{
		Height:         share.Height,
		SignerAddress:  share.SignerAddress,
		SignatureShare: share.SignatureShare,
	}
	entropyGenerator.entropyShares[newShare.Height][index] = newShare
	return nil
}

func (entropyGenerator *EntropyGenerator) GetEntropy(height int64) (types.ThresholdSignature, error) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if height < 0 {
		return nil, fmt.Errorf("negative height %v", height)
	}
	if entropyGenerator.entropyComputed[height] == nil {
		return nil, fmt.Errorf("entropy at height %v not yet computed", height)
	}
	return entropyGenerator.entropyComputed[height], nil
}

func (entropyGenerator *EntropyGenerator) GetEntropyShares(height int64) map[int]types.EntropyShare {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropySharesCopy := entropyGenerator.entropyShares[height]
	return entropySharesCopy
}

func (entropyGenerator *EntropyGenerator) GetThreshold() int {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	return entropyGenerator.threshold
}

func (entropyGenerator *EntropyGenerator) validInputs(height int64, index int) error {
	if index < 0 {
		return fmt.Errorf("invalid index %v", index)
	}
	if entropyGenerator.entropyComputed[height] != nil {
		return fmt.Errorf("already computed entropy at height %v", height)
	}
	if len(entropyGenerator.entropyShares[height][index].SignatureShare) != 0 {
		return fmt.Errorf("already have entropy share at height %v index %v", height, index)
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign(height int64) {
	index, _ := entropyGenerator.Validators.GetByAddress(entropyGenerator.privValidator.GetPubKey().Address())
	err := entropyGenerator.validInputs(height + 1, index)
	if  err != nil {
		entropyGenerator.Logger.Error(err.Error())
		return
	}
	if !entropyGenerator.aeonExecUnit.CanSign() {
		entropyGenerator.Logger.Error("node can not sign entropy - no dkg private key")
		return
	}
	if entropyGenerator.entropyComputed[height] == nil {
		entropyGenerator.Logger.Error("sign on block height %v without previous entropy", height)
		return
	}


	message := string(tmhash.Sum(entropyGenerator.entropyComputed[height]))
	signature := entropyGenerator.aeonExecUnit.Sign(message)
	if !entropyGenerator.aeonExecUnit.Verify(message, signature, uint64(index)) {
		entropyGenerator.Logger.Error("sign on block height %v generated invalid signature", height)
		return
	}

	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[height + 1] == nil {
		entropyGenerator.entropyShares[height + 1] = make(map[int]types.EntropyShare)
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
	entropyGenerator.entropyShares[height + 1][index] = share
	entropyGenerator.evsw.FireEvent(types.EventEntropyShare, &share)
}

func (entropyGenerator *EntropyGenerator) computeEntropyRoutine() {
	for {
		entropyGenerator.receivedEntropyShare()
		time.Sleep(ComputeEntropySleepDuration)
	}
}

func (entropyGenerator *EntropyGenerator) receivedEntropyShare() {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()
	height := entropyGenerator.lastComputedEntropyHeight + 1
	if entropyGenerator.entropyComputed[height] != nil {
		entropyGenerator.Logger.Error("lastComputedEntropyHeight not updated!")
		entropyGenerator.lastComputedEntropyHeight++
		return
	}
	if len(entropyGenerator.entropyShares[height]) >= entropyGenerator.threshold {
		message := string(tmhash.Sum(entropyGenerator.entropyComputed[height - 1]))
		signatureShares := NewIntStringMap()
		defer DeleteIntStringMap(signatureShares)

		for key, share := range entropyGenerator.entropyShares[height] {
			signatureShares.Set(key, share.SignatureShare)
		}
		groupSignature := entropyGenerator.aeonExecUnit.ComputeGroupSignature(signatureShares)
		if !entropyGenerator.aeonExecUnit.VerifyGroupSignature(message, groupSignature) {
			entropyGenerator.Logger.Error("entropy_generator.VerifyGroupSignature == false")
			return
		}
		entropyGenerator.Logger.Info("New entropy computed", "height", height)
		entropyGenerator.entropyComputed[height] = []byte(groupSignature)
		entropyGenerator.lastComputedEntropyHeight++

		// Dispatch entropy to entropy channel
		if entropyGenerator.computedEntropyChannel != nil {
			entropyGenerator.computedEntropyChannel <- types.ComputedEntropy{
				Height:         height,
				GroupSignature: []byte(groupSignature),
			}
		}

		// Don't delete this yet as need them there for gossiping to peers
		//delete(entropyGenerator.entropyShares, height)

		// Continue onto the next random value
		entropyGenerator.sign(height)
	}
}
