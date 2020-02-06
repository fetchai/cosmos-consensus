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

type Signature = []byte

var GenesisHeight = int64(0)

type EntropyGenerator struct {
	Logger  log.Logger
	proxyMtx     sync.Mutex

	threshold int
	entropyShares map[int64]map[int]types.EntropyShare
	entropyComputed map[int64]Signature

	// To be safe, need to store set of validators who can participate in DRB here to avoid
	// possible problems with validator set changing allowed by Tendermint
	index int
	address crypto.Address
	Validators                  *types.ValidatorSet

	stopped bool
	// synchronous pubsub between consensus state and reactor.
	// state only emits EventNewRoundStep and EventVote
	evsw tmevents.EventSwitch
}

func NewEntropyGenerator(logger log.Logger) *EntropyGenerator {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	es := &EntropyGenerator{
		Logger: logger,
		entropyShares: make(map[int64]map[int]types.EntropyShare),
		entropyComputed: make(map[int64]Signature),
		index: -1,
		stopped: false,
		evsw:             tmevents.NewEventSwitch(),
	}
	return es
}

func (entropyGenerator *EntropyGenerator) SetValidatorsAndThreshold(validators *types.ValidatorSet, newThreshold int) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.Validators = validators
	entropyGenerator.threshold = newThreshold
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

func (entropyGenerator *EntropyGenerator) SetIndexAndAddress(newIndex int, address crypto.Address) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.index = newIndex
	entropyGenerator.address = address
}

func (entropyGenerator *EntropyGenerator) Start() error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if err := entropyGenerator.evsw.Start(); err != nil {
		return err
	}

	entropyGenerator.stopped = false
	entropyShare, err := entropyGenerator.sign(1)
	if err != nil {
		return err
	}
	entropyGenerator.evsw.FireEvent(types.EventEntropyShare, &entropyShare)
	return nil
}

func (entropyGenerator *EntropyGenerator) Stop() {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.evsw.Stop()

	entropyGenerator.stopped = true
}

func (entropyGenerator *EntropyGenerator) ApplyEntropyShare(index int, share *types.EntropyShare) error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	err := entropyGenerator.validInputs(share.Height, index)
	if  err != nil {
		return err
	}

	// TODO: Verification
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
		entropyGenerator.Logger.Info("New entropy computed", "height", share.Height)
		// TODO: Compute group signature
		entropyGenerator.entropyComputed[share.Height] = []byte("hello")
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
		err := fmt.Errorf("invalid index %v", index)
		return err
	}
	if entropyGenerator.entropyComputed[height] != nil {
		err := fmt.Errorf("already computed entropy at height %v", height)
		return err
	}
	if entropyGenerator.entropyShares[height][index].SignatureShare != nil {
		err := fmt.Errorf("already have entropy share at height %v index %v", height, index)
		return err
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign(height int64) (types.EntropyShare, error) {
	err := entropyGenerator.validInputs(height, entropyGenerator.index)
	if  err!= nil {
		return types.EntropyShare{}, err
	}
	if entropyGenerator.entropyComputed[height - 1] == nil {
		err = fmt.Errorf("sign on block height %v without previous entropy", height)
		return types.EntropyShare{}, err
	}

	// TODO: Sign and verify own signature
	signature := tmhash.Sum(entropyGenerator.entropyComputed[height - 1])
	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[height] == nil {
		entropyGenerator.entropyShares[height] = make(map[int]types.EntropyShare)
	}
	share := types.EntropyShare{
		Height:         height,
		SignerAddress:  entropyGenerator.address,
		SignatureShare: signature,
	}
	entropyGenerator.entropyShares[height][entropyGenerator.index] = share
	return share, nil
}
