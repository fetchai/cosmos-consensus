package beacon

import (
	"encoding/binary"
	"github.com/pkg/errors"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/consensus"
	cstypes "github.com/tendermint/tendermint/consensus/types"
	"github.com/tendermint/tendermint/crypto/tmhash"
	sm "github.com/tendermint/tendermint/state"
	"math/rand"
	"sort"
	"time"

	"github.com/tendermint/tendermint/types"
)

//-----------------------------------------------------------------------------
// Errors

var (
	ErrInvalidProposalSignature = errors.New("error invalid proposal signature")
	ErrInvalidProposalPOLRound  = errors.New("error invalid proposal POL round")
)

//-----------------------------------------------------------------------------

// internally generated messages which may update the state
type timeoutInfo struct {
	Duration time.Duration         `json:"duration"`
	Height   int64                 `json:"height"`
	Round    int                   `json:"round"`
	Step     cstypes.RoundStepType `json:"step"`
}

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
// It processes votes and proposals, and upon reaching agreement,
// commits blocks to the chain and executes them against the application.
// The internal state machine receives input from peers, the internal validator, and from a timer.
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
