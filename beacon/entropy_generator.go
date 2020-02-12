package beacon

import (
	"fmt"
	"github.com/tendermint/tendermint/crypto"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/types"
	"sort"
	"sync"

	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/log"
)

var (
	EntropyChannelCapacity = 5
)

type EntropyGenerator struct {
	Logger  log.Logger
	proxyMtx     sync.Mutex

	threshold int
	entropyShares map[int64]map[int]types.EntropyShare
	entropyComputed map[int64]types.ThresholdSignature

	// Channel for sending off entropy for receiving elsewhere
	computedEntropyChannel chan<- types.ComputedEntropy

	// To be safe, need to store set of validators who can participate in DRB here to avoid
	// possible problems with validator set changing allowed by Tendermint
	privKey  crypto.PrivKey
	Validators                  *types.ValidatorSet
	aeonExecUnit AeonExecUnit

	stopped bool
	// synchronous pubsub between consensus state and reactor.
	// state only emits EventNewRoundStep and EventVote
	evsw tmevents.EventSwitch

	// For signing entropy messages
	chainID string
}

func NewEntropyGenerator(logger log.Logger, validators *types.ValidatorSet, newPrivKey crypto.PrivKey, newChainID string) *EntropyGenerator {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	es := &EntropyGenerator{
		Logger: logger,
		entropyShares: make(map[int64]map[int]types.EntropyShare),
		entropyComputed: make(map[int64]types.ThresholdSignature),
		privKey: newPrivKey,
		Validators: validators,
		stopped: true,
		evsw:             tmevents.NewEventSwitch(),
		chainID: newChainID,
	}

	es.threshold = es.Validators.Size() / 2 + 1
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

	// Only allow updating of aeon keys if generator is stopped
	if entropyGenerator.stopped {
		entropyGenerator.aeonExecUnit = aeonKeys
	}
}

func (entropyGenerator *EntropyGenerator) SetComputedEntropyChannel(entropyChannel chan<- types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.computedEntropyChannel == nil {
		entropyGenerator.computedEntropyChannel = entropyChannel
	}
}

// Generates entropy from the last computed entropy height
func (entropyGenerator *EntropyGenerator) Start() error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.stopped {
		if entropyGenerator.aeonExecUnit.Swigcptr() == 0 {
			return fmt.Errorf("no active execution unit")
		}
		if err := entropyGenerator.evsw.Start(); err != nil {
			return err
		}

		entropyGenerator.stopped = false

		// Find last computed entropy height
		entropyHeights := make([]int64, 0, len(entropyGenerator.entropyComputed))
		for height := range entropyGenerator.entropyComputed {
			entropyHeights = append(entropyHeights, height)
		}
		sort.Slice(entropyHeights, func(i int, j int ) bool {
			return entropyHeights[i] < entropyHeights[j]
		})
		lastComputedEntropyHeight := entropyHeights[len(entropyGenerator.entropyComputed) - 1]

		entropyShare, err := entropyGenerator.sign(lastComputedEntropyHeight)
		if err != nil {
			return err
		}
		entropyGenerator.evsw.FireEvent(types.EventEntropyShare, &entropyShare)
		return nil
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) Stop() {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if !entropyGenerator.stopped {
		entropyGenerator.evsw.Stop()

		entropyGenerator.stopped = true

		// Close channel to notify receiver than no more entropy is being generated
		if entropyGenerator.computedEntropyChannel != nil {
			close(entropyGenerator.computedEntropyChannel)
		}

		// Put this here for now but should not be here
		defer DeleteAeonExecUnit(entropyGenerator.aeonExecUnit)
	}
}

func (entropyGenerator *EntropyGenerator) ApplyEntropyShare(share *types.EntropyShare) error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.stopped {
		return fmt.Errorf("entropy generator stopped")
	}
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
	entropyGenerator.entropyShares[share.Height][index] = newShare

	if len(entropyGenerator.entropyShares[share.Height]) >= entropyGenerator.threshold {
		signatureShares := NewIntStringMap()
		defer DeleteIntStringMap(signatureShares)

		for key, share := range entropyGenerator.entropyShares[share.Height] {
			signatureShares.Set(key, share.SignatureShare)
		}
		groupSignature := entropyGenerator.aeonExecUnit.ComputeGroupSignature(signatureShares)
		if !entropyGenerator.aeonExecUnit.VerifyGroupSignature(message, groupSignature) {
			return fmt.Errorf("entropy_generator.VerifyGroupSignature == false")
		}
		entropyGenerator.Logger.Info("New entropy computed", "height", share.Height)
		entropyGenerator.entropyComputed[share.Height] = []byte(groupSignature)

		// Dispatch entropy to entropy channel
		if entropyGenerator.computedEntropyChannel != nil {
			entropyGenerator.computedEntropyChannel <- types.ComputedEntropy{
				Height:         share.Height,
				GroupSignature: []byte(groupSignature),
			}
		}

		// Don't delete this yet as need them there for gossiping to peers
		//delete(entropyGenerator.entropyShares, height)

		// Continue onto the next random value
		if !entropyGenerator.stopped {
			entropyGenerator.sign(share.Height)
		}
	}
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

func (entropyGenerator *EntropyGenerator) sign(height int64) (types.EntropyShare, error) {
	index, _ := entropyGenerator.Validators.GetByAddress(entropyGenerator.privKey.PubKey().Address())
	err := entropyGenerator.validInputs(height + 1, index)
	if  err != nil || !entropyGenerator.aeonExecUnit.CanSign() {
		return types.EntropyShare{}, err
	}
	if entropyGenerator.entropyComputed[height] == nil {
		return types.EntropyShare{}, fmt.Errorf("sign on block height %v without previous entropy", height)
	}


	message := string(tmhash.Sum(entropyGenerator.entropyComputed[height]))
	signature := entropyGenerator.aeonExecUnit.Sign(message)
	if !entropyGenerator.aeonExecUnit.Verify(message, signature, uint64(index)) {
		return types.EntropyShare{}, fmt.Errorf("sign on block height %v generated invalid signature", height)
	}

	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[height + 1] == nil {
		entropyGenerator.entropyShares[height + 1] = make(map[int]types.EntropyShare)
	}
	share := types.EntropyShare{
		Height:         height + 1,
		SignerAddress:  entropyGenerator.privKey.PubKey().Address(),
		SignatureShare: signature,
	}
	// Sign message
	share.Signature, err = entropyGenerator.privKey.Sign(share.SignBytes(entropyGenerator.chainID))
	if err != nil {
		return types.EntropyShare{}, nil
	}
	entropyGenerator.entropyShares[height + 1][index] = share
	return share, nil
}
