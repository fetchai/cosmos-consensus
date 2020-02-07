package beacon

import (
	"fmt"
	"github.com/tendermint/tendermint/crypto"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/types"
	"sync"

	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/log"
)

var (
	EntropyChannelCapacity = 5
)

type ComputedEntropy struct {
	Height int64
	GroupSignature Signature
}

type EntropyGenerator struct {
	Logger  log.Logger
	proxyMtx     sync.Mutex

	threshold int
	entropyShares map[int64]map[int]EntropyShare
	entropyComputed map[int64]Signature

	// Channel for sending off entropy for receiving elsewhere
	computedEntropyChannel chan<-ComputedEntropy

	// To be safe, need to store set of validators who can participate in DRB here to avoid
	// possible problems with validator set changing allowed by Tendermint
	address crypto.Address
	Validators                  *types.ValidatorSet
	aeonExecUnit AeonExecUnit

	stopped bool
	// synchronous pubsub between consensus state and reactor.
	// state only emits EventNewRoundStep and EventVote
	evsw tmevents.EventSwitch
}

func NewEntropyGenerator(logger log.Logger, validators *types.ValidatorSet, newAddress crypto.Address) *EntropyGenerator {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	es := &EntropyGenerator{
		Logger: logger,
		entropyShares: make(map[int64]map[int]EntropyShare),
		entropyComputed: make(map[int64]Signature),
		address: newAddress,
		Validators: validators,
		stopped: true,
		evsw:             tmevents.NewEventSwitch(),
	}

	es.threshold = es.Validators.Size() / 2 + 1
	return es
}

func (entropyGenerator *EntropyGenerator) SetGenesisEntropy(genEntropy Signature) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.entropyComputed[GenesisHeight] != nil {
		entropyGenerator.Logger.Error("Attempt to reset genesis entropy")
		return
	}
	entropyGenerator.entropyComputed[GenesisHeight] = genEntropy
}

func (entropyGenerator *EntropyGenerator) SetAeonKeys(aeon_keys DKGKeyInformation, generator string) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	// Only allow updating of aeon keys if generator is stopped
	if entropyGenerator.stopped {
		entropyGenerator.aeonExecUnit = NewAeonExecUnit(aeon_keys, generator)
	}
}

func (entropyGenerator *EntropyGenerator) SetComputedEntropyChannel(entropyChannel chan<-ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.computedEntropyChannel == nil {
		entropyGenerator.computedEntropyChannel = entropyChannel
	}
}

// Only for demo as always generates entropy from genesis - should be coupled
// to consensus state
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
		entropyShare, err := entropyGenerator.sign(GenesisHeight + 1)
		if err != nil {
			return err
		}
		entropyGenerator.evsw.FireEvent(EventEntropyShare, &entropyShare)
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

func (entropyGenerator *EntropyGenerator) ApplyEntropyShare(index int, share *EntropyShare) error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.stopped {
		return fmt.Errorf("entropy generator stopped")
	}
	err := entropyGenerator.validInputs(share.Height, index)
	if  err != nil {
		return err
	}

	// Verify share
	message := string(tmhash.Sum(entropyGenerator.entropyComputed[share.Height - 1]))
	if !entropyGenerator.aeonExecUnit.Verify(message, share.SignatureShare, uint64(index)) {
		return fmt.Errorf("invalid entropy share received from %v", share.SignerAddress)
	}

	entropyGenerator.Logger.Info("New entropy share received", "height", share.Height, "validator index", index)
	if entropyGenerator.entropyShares[share.Height] == nil {
		entropyGenerator.entropyShares[share.Height] = make(map[int]EntropyShare)
	}
	newShare := EntropyShare{
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
			entropyGenerator.computedEntropyChannel <- ComputedEntropy{
				Height:         share.Height,
				GroupSignature: []byte(groupSignature),
			}
		}

		// Don't delete this yet as need them there for gossiping to peers
		//delete(entropyGenerator.entropyShares, height)

		// Continue onto the next random value
		if !entropyGenerator.stopped {
			entropyGenerator.sign(share.Height + 1)
		}
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) GetEntropy(height int64) (Signature, error) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if height < 0 {
		err := fmt.Errorf("negative height %v", height)
		return nil, err
	}
	if entropyGenerator.entropyComputed[height] == nil {
		err := fmt.Errorf("entropy at height %v not yet computed", height)
		return nil, err
	}
	return entropyGenerator.entropyComputed[height], nil
}

func (entropyGenerator *EntropyGenerator) GetEntropyShares(height int64) map[int]EntropyShare {
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
		err := fmt.Errorf("invalid index %v", index)
		return err
	}
	if entropyGenerator.entropyComputed[height] != nil {
		err := fmt.Errorf("already computed entropy at height %v", height)
		return err
	}
	if len(entropyGenerator.entropyShares[height][index].SignatureShare) != 0 {
		err := fmt.Errorf("already have entropy share at height %v index %v", height, index)
		return err
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign(height int64) (EntropyShare, error) {
	index, _ := entropyGenerator.Validators.GetByAddress(entropyGenerator.address)
	err := entropyGenerator.validInputs(height, index)
	if  err!= nil {
		return EntropyShare{}, err
	}
	if entropyGenerator.entropyComputed[height - 1] == nil {
		err = fmt.Errorf("sign on block height %v without previous entropy", height)
		return EntropyShare{}, err
	}


	message := string(tmhash.Sum(entropyGenerator.entropyComputed[height - 1]))
	signature := entropyGenerator.aeonExecUnit.Sign(message)
	if !entropyGenerator.aeonExecUnit.Verify(message, signature, uint64(index)) {
		err = fmt.Errorf("sign on block height %v generated invalid signature", height)
		return EntropyShare{}, err
	}

	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[height] == nil {
		entropyGenerator.entropyShares[height] = make(map[int]EntropyShare)
	}
	share := EntropyShare{
		Height:         height,
		SignerAddress:  entropyGenerator.address,
		SignatureShare: signature,
	}
	entropyGenerator.entropyShares[height][index] = share
	return share, nil
}
