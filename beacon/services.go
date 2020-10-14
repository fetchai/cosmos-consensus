package beacon

import (
	"github.com/tendermint/tendermint/types"
)

// Interface for evidence pool
type evidencePool interface {
	AddEvidence(types.Evidence) error
	PendingEvidence(int64) []types.Evidence
}

// Mock evidence pool for tests
type mockEvidencePool struct {
	receivedEvidence []types.Evidence
}

func newMockEvidencePool() *mockEvidencePool {
	return &mockEvidencePool{
		receivedEvidence: make([]types.Evidence, 0),
	}
}

func (mep *mockEvidencePool) AddEvidence(ev types.Evidence) error {
	mep.receivedEvidence = append(mep.receivedEvidence, ev)
	return nil
}

func (mep *mockEvidencePool) PendingEvidence(int64) []types.Evidence {
	return mep.receivedEvidence
}
