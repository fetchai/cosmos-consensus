package types

import (
	"fmt"
	"sync"
	"time"

	"github.com/tendermint/tendermint/libs/bits"
	"github.com/tendermint/tendermint/types"
)

//-----------------------------------------------------------------------------

// PeerRoundState contains the known state of a peer.
// NOTE: Read-only when returned by PeerState.GetRoundState().
type PeerRoundState struct {
	Height int64         `json:"height"` // Height peer is at
	Round  int           `json:"round"`  // Round peer is at, -1 if unknown.
	Step   RoundStepType `json:"step"`   // Step peer is at

	// Estimated start of round 0 at this height
	StartTime time.Time `json:"start_time"`

	// True if peer has proposal for this round
	Proposal                 bool                `json:"proposal"`
	ProposalBlockPartsHeader types.PartSetHeader `json:"proposal_block_parts_header"` //
	ProposalBlockParts       *bits.BitArray      `json:"proposal_block_parts"`        //
	ProposalPOLRound         int                 `json:"proposal_pol_round"`          // Proposal's POL round. -1 if none.

	// nil until ProposalPOLMessage received.
	ProposalPOL     *bits.BitArray   `json:"proposal_pol"`
	Prevotes        *bits.BitArray   `json:"prevotes"`          // All votes peer has for this round
	Precommits      *PrecommitRecord `json:"precommits"`        // All precommits peer has for this round
	LastCommitRound int              `json:"last_commit_round"` // Round of commit for last height. -1 if none.
	LastCommit      *PrecommitRecord `json:"last_commit"`       // All commit precommits of commit for last height

	// Round that we have commit for. Not necessarily unique. -1 if none.
	CatchupCommitRound int `json:"catchup_commit_round"`

	// All commit precommits peer has for this height & CatchupCommitRound
	CatchupCommit *PrecommitRecord `json:"catchup_commit"`
}

// String returns a string representation of the PeerRoundState
func (prs PeerRoundState) String() string {
	return prs.StringIndented("")
}

// StringIndented returns a string representation of the PeerRoundState
func (prs PeerRoundState) StringIndented(indent string) string {
	return fmt.Sprintf(`PeerRoundState{
%s  %v/%v/%v @%v
%s  Proposal %v -> %v
%s  POL      %v (round %v)
%s  Prevotes   %v
%s  Precommits %v
%s  LastCommit %v (round %v)
%s  Catchup    %v (round %v)
%s}`,
		indent, prs.Height, prs.Round, prs.Step, prs.StartTime,
		indent, prs.ProposalBlockPartsHeader, prs.ProposalBlockParts,
		indent, prs.ProposalPOL, prs.ProposalPOLRound,
		indent, prs.Prevotes,
		indent, prs.Precommits,
		indent, prs.LastCommit, prs.LastCommitRound,
		indent, prs.CatchupCommit, prs.CatchupCommitRound,
		indent)
}

//-----------------------------------------------------------
// These methods are for Protobuf Compatibility

// Size returns the size of the amino encoding, in bytes.
func (prs *PeerRoundState) Size() int {
	bs, _ := prs.Marshal()
	return len(bs)
}

// Marshal returns the amino encoding.
func (prs *PeerRoundState) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryBare(prs)
}

// MarshalTo calls Marshal and copies to the given buffer.
func (prs *PeerRoundState) MarshalTo(data []byte) (int, error) {
	bs, err := prs.Marshal()
	if err != nil {
		return -1, err
	}
	return copy(data, bs), nil
}

// Unmarshal deserializes from amino encoded form.
func (prs *PeerRoundState) Unmarshal(bs []byte) error {
	return cdc.UnmarshalBinaryBare(bs, prs)
}

//-----------------------------------------------------------
// Thread safe map for recording precommits seen by peer

type PrecommitRecord struct {
	record map[string]struct{} // All precommits peer has, identified by validator index and timestamp
	mtx    sync.RWMutex
}

func NewPrecommitRecord() *PrecommitRecord {
	return &PrecommitRecord{
		record: map[string]struct{}{},
	}
}

func (pr *PrecommitRecord) HasVote(identifier string) bool {
	pr.mtx.RLock()
	defer pr.mtx.RUnlock()

	_, hasVote := pr.record[identifier]
	return hasVote
}

func (pr *PrecommitRecord) SetHasVote(identifier string) {
	if pr == nil {
		return
	}

	pr.mtx.Lock()
	defer pr.mtx.Unlock()

	pr.record[identifier] = struct{}{}
}

// BitArray returns bit array of whether peer has seen a precommit from a certain validator, identified
// by their index
func (pr *PrecommitRecord) BitArray(numValidators int) *bits.BitArray {
	if pr == nil {
		return nil
	}

	pr.mtx.RLock()
	defer pr.mtx.RUnlock()

	bitArray := bits.NewBitArray(numValidators)
	for key := range pr.record {
		bitArray.SetIndex(types.PrecommitIdentifierToIndex(key), true)
	}
	return bitArray
}
