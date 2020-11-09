package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	amino "github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto/bls12_381"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/libs/bits"
	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/mcl_cpp"
	tmproto "github.com/tendermint/tendermint/proto/types"
)

// SeenCommit is the commit, either BlockCommit or VotesCommit, seen to verify a block
type SeenCommit interface {
	GetRound() int
	GetBlockID() BlockID
}

// ConsensusLastCommit used for LastCommit in consensus state, which can
// be either BlockCommit or PrecommitSet depending on whether the LastCommit
// was fetched from the block, or from local seen votes
type ConsensusLastCommit interface {
	GetHeight() int64
	GetRound() int
	Size() int
	IsCommit() bool
	HasTwoThirdsMajority() bool
	MakeBlockCommit() *BlockCommit
	GetVoteTimestamps(index int) []time.Time
	GetByIndex(index int, timestamp time.Time) *Vote
	AddVote(vote *Vote) (bool, error)
	StringShort() string
	HasAll() bool
}

var _ SeenCommit = &BlockCommit{}
var _ ConsensusLastCommit = &BlockCommit{}

// BlockCommit contains the evidence that a block was committed by a set of validators.
// In particular, it does not contain the vote signatures of each validator and instead stores
// the combined signature
// NOTE: BlockCommit is empty for height 1, but never nil.
type BlockCommit struct {
	// NOTE: The signatures are in order of address to preserve the bonded
	// ValidatorSet order.
	// Any peer with a block can gossip signatures by index with a peer without
	// recalculating the active ValidatorSet.
	Height            int64            `json:"height"`
	Round             int              `json:"round"`
	BlockID           BlockID          `json:"block_id"`
	Signatures        []CommitSigBlock `json:"signatures"`
	CombinedSignature string           `json:"combined_signature"`

	// Memoized in first call to corresponding method.
	// NOTE: can't memoize in constructor because constructor isn't used for
	// unmarshaling.
	hash     tmbytes.HexBytes
	bitArray *bits.BitArray
}

// NewBlockCommit returns a new BlockCommit from the CommitSigVotes for each validator by computing the
// combined signature
func NewBlockCommit(height int64, round int, blockID BlockID, commitSigs [][]CommitSigVote) *BlockCommit {
	// Compute combined signature by combining signatures for the block in order of validator
	// index. CombinedSignature in the commit will be empty if any of the individual signatures
	// does not correspond to the correct mcl signature type
	sigs := mcl_cpp.NewStringVector()
	blockCommit := make([]CommitSigBlock, len(commitSigs))
	defer mcl_cpp.DeleteStringVector(sigs)
	for idx, commitSigs := range commitSigs {
		if len(commitSigs) == 0 {
			blockCommit[idx] = NewCommitSigBlockAbsent()
			continue
		}
		blockCommit[idx] = CommitSigBlock{
			BlockIDFlag:      commitSigs[0].BlockIDFlag,
			ValidatorAddress: commitSigs[0].ValidatorAddress,
			Timestamp:        commitSigs[0].Timestamp,
		}
		// Exclude sigs which are for nil or are absent
		if commitSigs[0].ForBlock() {
			sigs.Add(string(commitSigs[0].Signature))
		}

	}
	return &BlockCommit{
		Height:            height,
		Round:             round,
		BlockID:           blockID,
		Signatures:        blockCommit,
		CombinedSignature: mcl_cpp.CombineSignatures(sigs),
	}
}

// VotesToBlockCommit returns a new BlockCommit from the CommitSigVotes for each validator by computing the
// combined signature
func VotesToBlockCommit(votesCommit *VotesCommit) *BlockCommit {
	// Compute combined signature by combining signatures for the block in order of validator
	// index. CombinedSignature in the commit will be empty if any of the individual signatures
	// does not correspond to the correct mcl signature type
	sigs := mcl_cpp.NewStringVector()
	blockCommit := make([]CommitSigBlock, len(votesCommit.Signatures))
	defer mcl_cpp.DeleteStringVector(sigs)
	for idx, commitSigs := range votesCommit.Signatures {
		if len(commitSigs) == 0 {
			blockCommit[idx] = NewCommitSigBlockAbsent()
			continue
		}
		blockCommit[idx] = CommitSigBlock{
			BlockIDFlag:      commitSigs[0].BlockIDFlag,
			ValidatorAddress: commitSigs[0].ValidatorAddress,
			Timestamp:        commitSigs[0].Timestamp,
		}
		// Exclude sigs which are for nil or are absent
		if commitSigs[0].ForBlock() {
			sigs.Add(string(commitSigs[0].Signature))
		}

	}
	return &BlockCommit{
		Height:            votesCommit.Height,
		Round:             votesCommit.Round,
		BlockID:           votesCommit.BlockID,
		Signatures:        blockCommit,
		CombinedSignature: mcl_cpp.CombineSignatures(sigs),
	}
}

// VoteSignBytes constructs the SignBytes that validators would have signed
func (commit *BlockCommit) VoteSignBytes(votePrefix string) []byte {
	vote := Vote{
		Type:    PrecommitType,
		Height:  commit.Height,
		Round:   commit.Round,
		BlockID: commit.BlockID,
	}
	return vote.SignBytes(votePrefix)
}

// Type returns the vote type of the commit, which is always VoteTypePrecommit
func (commit *BlockCommit) Type() byte {
	return byte(PrecommitType)
}

// GetHeight returns height of the commit.
// Implements ConsensusLastCommit
func (commit *BlockCommit) GetHeight() int64 {
	return commit.Height
}

// GetRound returns height of the commit.
// Implements GossipCommit.
func (commit *BlockCommit) GetRound() int {
	return commit.Round
}

// Size returns the number of signatures in the commit.
func (commit *BlockCommit) Size() int {
	if commit == nil {
		return 0
	}
	return len(commit.Signatures)
}

// IsCommit returns whether BlockCommit contains +2/3 votes for block
// Implements ConsensusLastCommit
func (commit *BlockCommit) IsCommit() bool {
	if commit == nil {
		return false
	}
	return true
}

// GetBlockID returns blockID in commit
// Implements GossipCommit
func (commit *BlockCommit) GetBlockID() BlockID {
	return commit.BlockID
}

// BitArray returns a BitArray of which validators voted for BlockID or nil in this commit.
// Implements ConsensusLastCommit
func (commit *BlockCommit) BitArray() *bits.BitArray {
	if commit.bitArray == nil {
		commit.bitArray = bits.NewBitArray(len(commit.Signatures))
		for i, commitSig := range commit.Signatures {
			// TODO: need to check the BlockID otherwise we could be counting conflicts,
			// not just the one with +2/3 !
			commit.bitArray.SetIndex(i, !commitSig.Absent())
		}
	}
	return commit.bitArray
}

// ValidateBasic performs basic validation that doesn't involve state data.
// Does not actually check the cryptographic signatures.
func (commit *BlockCommit) ValidateBasic() error {
	if commit.Height < 0 {
		return errors.New("negative Height")
	}
	if commit.Round < 0 {
		return errors.New("negative Round")
	}
	if commit.Height >= 1 {
		if commit.BlockID.IsZero() {
			return errors.New("commit cannot be for nil block")
		}

		if len(commit.Signatures) == 0 {
			return errors.New("no signatures in commit")
		}
		for i, commitSig := range commit.Signatures {
			if err := commitSig.ValidateBasic(); err != nil {
				return fmt.Errorf("wrong CommitSig #%d: %v", i, err)
			}
		}
		if len(commit.CombinedSignature) == 0 {
			return errors.New("empty combined signature")
		}
		if len(commit.CombinedSignature) > bls12_381.SignatureSize {
			return fmt.Errorf("invalid combined signature size: expected %v, got %v", bls12_381.SignatureSize,
				len(commit.CombinedSignature))
		}
	}

	return nil
}

// Hash returns the hash of the commit.
func (commit *BlockCommit) Hash() tmbytes.HexBytes {
	if commit == nil {
		return nil
	}
	if commit.hash == nil {
		bs := make([][]byte, len(commit.Signatures)+1)
		for i, commitSig := range commit.Signatures {
			bs[i] = cdcEncode(commitSig)
		}
		commit.hash = merkle.SimpleHashFromByteSlices(bs)
		bs[len(commit.Signatures)] = []byte(commit.CombinedSignature)
	}
	return commit.hash
}

// StringIndented returns a string representation of the commit
func (commit *BlockCommit) StringIndented(indent string) string {
	if commit == nil {
		return "nil-Commit"
	}
	commitSigStrings := make([]string, len(commit.Signatures))
	for i, commitSig := range commit.Signatures {
		commitSigStrings[i] = commitSig.String()
	}
	return fmt.Sprintf(`Commit{
%s  Height:            %d
%s  Round:             %d
%s  BlockID:           %v
%s  CombinedSignature: %s
%s  Signatures:
%s    %v
%s}#%v`,
		indent, commit.Height,
		indent, commit.Round,
		indent, commit.BlockID,
		indent, commit.CombinedSignature,
		indent,
		indent, strings.Join(commitSigStrings, "\n"+indent+"    "),
		indent, commit.hash)
}

// HasTwoThirdsMajority implements ConsensusLastCommit
func (commit *BlockCommit) HasTwoThirdsMajority() bool {
	return true
}

// GetVoteTimestamps implements ConsensusLastCommit
func (commit *BlockCommit) GetVoteTimestamps(index int) []time.Time {
	return []time.Time{}
}

// MakeBlockCommit implements ConsensusLastCommit
func (commit *BlockCommit) MakeBlockCommit() *BlockCommit {
	return commit
}

// GetByIndex implements ConsensusLastCommit
func (commit *BlockCommit) GetByIndex(index int, timestamp time.Time) *Vote {
	return nil
}

// AddVote implements ConsensusLastCommit
func (commit *BlockCommit) AddVote(vote *Vote) (bool, error) {
	return false, fmt.Errorf("can not add vote to BlockCommit")
}

// StringShort implements ConsensusLastCommit
func (commit *BlockCommit) StringShort() string {
	return fmt.Sprintf(`BlockCommit{H:%v R:%v BlockID:%v %v %v}`,
		commit.Height, commit.Round, commit.BlockID, commit.BitArray(), commit.CombinedSignature)
}

// HasAll implements ConsensusLastCommit
func (commit *BlockCommit) HasAll() bool {
	return true
}

// ToProto converts BlockCommit to protobuf
func (commit *BlockCommit) ToProto() *tmproto.Commit {
	if commit == nil {
		return nil
	}

	c := new(tmproto.Commit)
	sigs := make([]tmproto.CommitSig, len(commit.Signatures))
	for i := range commit.Signatures {
		sigs[i] = *commit.Signatures[i].ToProto()
	}
	c.Signatures = sigs

	c.Height = commit.Height
	c.Round = int32(commit.Round)
	c.BlockID = commit.BlockID.ToProto()
	if commit.hash != nil {
		c.Hash = commit.hash
	}
	c.BitArray = commit.bitArray.ToProto()
	c.CombinedSignature = commit.CombinedSignature
	return c
}

// BlockCommitFromProto sets a protobuf BlockCommit to the given pointer.
// It returns an error if the commit is invalid.
func BlockCommitFromProto(cp *tmproto.Commit) (*BlockCommit, error) {
	if cp == nil {
		return nil, errors.New("nil Commit")
	}

	var (
		commit   = new(BlockCommit)
		bitArray *bits.BitArray
	)

	bi, err := BlockIDFromProto(&cp.BlockID)
	if err != nil {
		return nil, err
	}

	bitArray.FromProto(cp.BitArray)

	sigs := make([]CommitSigBlock, len(cp.Signatures))
	for i := range cp.Signatures {
		if err := sigs[i].FromProto(cp.Signatures[i]); err != nil {
			return nil, err
		}
	}
	commit.Signatures = sigs

	commit.Height = cp.Height
	commit.Round = int(cp.Round)
	commit.BlockID = *bi
	commit.hash = cp.Hash
	commit.bitArray = bitArray
	commit.CombinedSignature = cp.CombinedSignature

	return commit, commit.ValidateBasic()
}

//--------------------------------------------------------------------------------------

var _ SeenCommit = &VotesCommit{}

// VotesCommit contains the evidence that a block was committed by a set of validators.
// Contains all signatures required to verify information in votes and stores multiple votes
// from the same validator with different timestamps. Mainly used for saving votes to store.
// NOTE: Commit is empty for height 1, but never nil.
type VotesCommit struct {
	// NOTE: The signatures are in order of address to preserve the bonded
	// ValidatorSet order.
	// Any peer with a block can gossip signatures by index with a peer without
	// recalculating the active ValidatorSet.
	Height     int64             `json:"height"`
	Round      int               `json:"round"`
	BlockID    BlockID           `json:"block_id"`
	Signatures [][]CommitSigVote `json:"signatures"`

	// Memoized in first call to corresponding method.
	// NOTE: can't memoize in constructor because constructor isn't used for
	// unmarshaling.
	hash     tmbytes.HexBytes
	bitArray *bits.BitArray
}

func newVotesCommit(height int64, round int, blockID BlockID, commitSigs [][]CommitSigVote) *VotesCommit {
	return &VotesCommit{
		Height:     height,
		Round:      round,
		BlockID:    blockID,
		Signatures: commitSigs,
	}
}

// CommitToVoteSet constructs a PrecommitSet from the VotesCommit and validator set.
// Panics if signatures from the commit can't be added to the precommit set.
// Inverse of PrecommitSet.MakeCommit().
func CommitToVoteSet(chainID string, seenCommit SeenCommit, vals *ValidatorSet) (*PrecommitSet, error) {
	commit, ok := seenCommit.(*VotesCommit)
	if !ok {
		return nil, fmt.Errorf("seenCommit of incorrect type: Require VotesCommit, got %T", seenCommit)
	}
	voteSet := NewPrecommitSet(chainID, commit.Height, commit.Round, vals)
	var err error
	for idx, commitSigs := range commit.Signatures {
		for voteIndex, commitSig := range commitSigs {
			if commitSig.Absent() {
				continue // OK, some precommits can be missing.
			}
			if v := commit.getVote(idx, voteIndex); v != nil {
				added, err := voteSet.AddVote(v)
				if err != nil {
					vote := commit.getVote(idx, voteIndex)
					_, val := voteSet.valSet.GetByIndex(vote.ValidatorIndex)
					voteSet.addVerifiedVote(vote, vote.BlockID.Key(), val.VotingPower)
				} else if !added || err != nil {
					panic(fmt.Sprintf("Failed to reconstruct LastCommit: %v", err))
				}
			}
		}
	}
	return voteSet, err
}

// getVote converts the CommitSig for the given valIdx to a Vote.
// Returns nil if the precommit at valIdx is nil.
// Panics if valIdx >= commit.Size().
func (commit *VotesCommit) getVote(valIdx int, voteIdx int) *Vote {
	commitSigs := commit.Signatures[valIdx]
	if voteIdx > len(commitSigs)-1 {
		return nil
	}
	commitSig := commitSigs[voteIdx]
	return &Vote{
		Type:               PrecommitType,
		Height:             commit.Height,
		Round:              commit.Round,
		BlockID:            commitSig.BlockID(commit.BlockID),
		Timestamp:          commitSig.Timestamp,
		ValidatorAddress:   commitSig.ValidatorAddress,
		ValidatorIndex:     valIdx,
		Signature:          commitSig.Signature,
		TimestampSignature: commitSig.TimestampSignature,
	}
}

// GetRound returns height of the commit.
// Implements SeenCommit
func (commit *VotesCommit) GetRound() int {
	return commit.Round
}

// GetBlockID returns blockID in commit
// Implements SeenCommit
func (commit *VotesCommit) GetBlockID() BlockID {
	return commit.BlockID
}

// ValidateBasic performs basic validation that doesn't involve state data.
// Does not actually check the cryptographic signatures.
func (commit *VotesCommit) ValidateBasic() error {
	if commit.Height < 0 {
		return errors.New("negative Height")
	}
	if commit.Round < 0 {
		return errors.New("negative Round")
	}
	if commit.Height >= 1 {
		if commit.BlockID.IsZero() {
			return errors.New("commit cannot be for nil block")
		}

		if len(commit.Signatures) == 0 {
			return errors.New("no signatures in commit")
		}
		for i, commitSigs := range commit.Signatures {
			for _, commitSig := range commitSigs {
				if err := commitSig.ValidateBasic(); err != nil {
					return fmt.Errorf("wrong CommitSig #%d: %v", i, err)
				}
			}
		}
	}

	return nil
}

func RegisterCommits(cdc *amino.Codec) {
	cdc.RegisterInterface((*SeenCommit)(nil), nil)
	cdc.RegisterInterface((*ConsensusLastCommit)(nil), nil)
	cdc.RegisterConcrete(&BlockCommit{}, "tendermint/BlockCommit", nil)
	cdc.RegisterConcrete(&VotesCommit{}, "tendermint/VotesCommit", nil)
	cdc.RegisterConcrete(&PrecommitSet{}, "tendermint/PrecommitSet", nil)
}
