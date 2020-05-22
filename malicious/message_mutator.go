package malicious

import (
	"sync"

	"github.com/tendermint/tendermint/types"
)

type DKGMessageMutation uint

var (
	empty struct{}
)

const (
	// DKG message mutations in the order they should be executed
	DKGDuplicate DKGMessageMutation = iota
	DKGWithhold
)

// MessageMutator changes messages in the DKG and DRB for malicious actors
type MessageMutator struct {
	privValidator       types.PrivValidator
	dkgMessageMutations map[DKGMessageMutation]struct{}
	mtx                 sync.RWMutex
}

// NewMessageMutator creates a message mutator for malicious nodes
func NewMessageMutator(privValidator types.PrivValidator) *MessageMutator {
	return &MessageMutator{
		privValidator:       privValidator,
		dkgMessageMutations: make(map[DKGMessageMutation]struct{}),
	}
}

// SetDKGMessageMutation adds a mutation to the message mutators set of active ones
func (mutator *MessageMutator) SetDKGMessageMutation(mutation DKGMessageMutation, turnOn bool) {
	mutator.mtx.Lock()
	defer mutator.mtx.Unlock()

	if turnOn {
		mutator.dkgMessageMutations[mutation] = empty
	} else {
		delete(mutator.dkgMessageMutations, mutation)
	}
}

// ChangeDKGMessage mutates the given message according or the actions set and returns
// the new slice of DKG messages to be sent
func (mutator *MessageMutator) ChangeDKGMessage(msg *types.DKGMessage) []*types.DKGMessage {
	mutator.mtx.RLock()
	defer mutator.mtx.RUnlock()

	ret := []*types.DKGMessage{msg}
	for mutation := DKGMessageMutation(0); mutation < DKGWithhold+1; mutation++ {
		if _, haveMutation := mutator.dkgMessageMutations[mutation]; haveMutation {
			if mutation == DKGDuplicate {
				ret = append(ret, msg)
			} else if mutation == DKGWithhold {
				ret = []*types.DKGMessage{}
			}
		}
	}
	return ret
}
