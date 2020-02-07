package beacon

import (
	"encoding/binary"
	"github.com/pkg/errors"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/consensus"
	"github.com/tendermint/tendermint/crypto/tmhash"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	"math/rand"
	"sort"
)

//-----------------------------------------------------------------------------
// Errors

var (
	ErrInvalidProposalSignature = errors.New("error invalid proposal signature")
	ErrInvalidProposalPOLRound  = errors.New("error invalid proposal POL round")
)

//-----------------------------------------------------------------------------

// interface to the mempool
type txNotifier interface {
	TxsAvailable() <-chan struct{}
}

// interface to the evidence pool
type evidencePool interface {
	AddEvidence(types.Evidence) error
}

//-----------------------------------------------------------------------------

// State handles execution of the consensus algorithm.
type State struct {
	consensus.State
	// For receiving entropy
	computedEntropyChannel <-chan ComputedEntropy
}

func NewState(
	config *cfg.ConsensusConfig,
	state sm.State,
	blockExec *sm.BlockExecutor,
	blockStore sm.BlockStore,
	txNotifier txNotifier,
	evpool evidencePool,
	options ...consensus.StateOption,
) *State {
	cs := &State{}
	cs.State = *consensus.NewState(config, state, blockExec, blockStore, txNotifier, evpool, options ...)
	return cs
}

func (cs *State) SetEntropyChannel(channel <-chan ComputedEntropy) {
	cs.computedEntropyChannel = channel
}

// Overrides getProposer in consensus.State and uses entropy to shuffle cabinet
func (cs *State) getProposer(height int64, round int) *types.Validator {
	if cs.computedEntropyChannel == nil {
		return cs.Validators.GetProposer()
	} else {
		nextEntropy := <-cs.computedEntropyChannel
		if nextEntropy.Height != height {
			cs.Logger.Error("Invalid entropy", "fetch height", nextEntropy.Height, "state height", height)
			return nil
		} else {
			entropy := tmhash.Sum(nextEntropy.GroupSignature)
			return cs.shuffledCabinet(entropy)[round]
		}
	}
}

// Check that rand.Shuffle is same across different platforms
func (cs *State) shuffledCabinet(entropy []byte) types.ValidatorsByAddress {
	seed, n := binary.Varint(entropy)
	if n <= 0 {
		cs.Logger.Error("Entropy buffer of incorrect size")
		return nil
	}
	rand.Seed(seed)

	// Sort validators
	sortedValidators := types.ValidatorsByAddress(cs.Validators.Validators)
	sort.Sort(sortedValidators)

	rand.Shuffle(len(sortedValidators), func(i, j int) {
		sortedValidators.Swap(i, j)
	})
	return sortedValidators
}
