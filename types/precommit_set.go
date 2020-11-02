package types

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/libs/bits"
)

// VoteSet interface satisfied by PrecommitSet and PrevoteSet
type VoteSet interface {
	ChainID() string
	GetRound() int
	Size() int
	BitArray() *bits.BitArray
	AddVote(vote *Vote) (added bool, err error)
	SetPeerMaj23(peerID P2PID, blockID BlockID) error
	HasAll() bool
	HasTwoThirdsMajority() bool
	TwoThirdsMajority() (blockID BlockID, ok bool)
	ValidatorSetHash() []byte
	StringShort() string
	VoteStrings() []string
	BitArrayString() string
}

var _ VoteSet = &PrecommitSet{}

// PrecommitIdentifier is unique identifier for a precommit in each height and round
// Used in consensus reactor to record the precommits peers have seen
func PrecommitIdentifier(index int, timestamp time.Time) string {
	return fmt.Sprintf("%v/%s", index, CanonicalTime(timestamp))
}

// Converts precommit identifier back to the validator index
func PrecommitIdentifierToIndex(identifier string) int {
	indexTimestamp := strings.Split(identifier, "/")
	index, err := strconv.Atoi(indexTimestamp[0])
	if err != nil {
		panic(fmt.Sprintf("Error converting precommit identifier %v to index", identifier))
	}
	return index
}

// PrecommitSet collects precommit votes on blocks. Stores precommits on the same
// block but with different timestamp
type PrecommitSet struct {
	chainID string
	height  int64
	round   int
	valSet  *ValidatorSet

	mtx           sync.Mutex
	votesBitArray *bits.BitArray
	votes         map[int]map[string]*Vote        // Primary votes to share by validator index and timestamp
	sum           int64                           // Sum of voting power for seen votes, discounting conflicts
	maj23         *BlockID                        // First 2/3 majority seen
	votesByBlock  map[string]*blockPrecommitVotes // string(blockHash|blockParts) -> blockVotes
	peerMaj23s    map[P2PID]BlockID               // Maj23 for each peer
}

// NewPrecommitSet constructs a new PrecommitVoteSet struct used to accumulate votes for given height/round.
func NewPrecommitSet(chainID string, height int64, round int, valSet *ValidatorSet) *PrecommitSet {
	if height == 0 {
		panic("Cannot make VoteSet for height == 0, doesn't make sense.")
	}
	precommitSet := &PrecommitSet{
		chainID:       chainID,
		height:        height,
		round:         round,
		valSet:        valSet,
		votesBitArray: bits.NewBitArray(valSet.Size()),
		votes:         make(map[int]map[string]*Vote, valSet.Size()),
		sum:           0,
		maj23:         nil,
		votesByBlock:  make(map[string]*blockPrecommitVotes, valSet.Size()),
		peerMaj23s:    make(map[P2PID]BlockID),
	}

	// Initialise nested map
	for index := 0; index < valSet.Size(); index++ {
		precommitSet.votes[index] = map[string]*Vote{}
	}

	return precommitSet
}

func (voteSet *PrecommitSet) ChainID() string {
	return voteSet.chainID
}

func (voteSet *PrecommitSet) GetHeight() int64 {
	if voteSet == nil {
		return 0
	}
	return voteSet.height
}

func (voteSet *PrecommitSet) GetRound() int {
	if voteSet == nil {
		return -1
	}
	return voteSet.round
}

func (voteSet *PrecommitSet) Size() int {
	if voteSet == nil {
		return 0
	}
	return voteSet.valSet.Size()
}

// Implements VoteSet
func (voteSet *PrecommitSet) ValidatorSetHash() []byte {
	if voteSet == nil {
		return []byte{}
	}
	return voteSet.valSet.Hash()
}

// Returns added=true if vote is valid and new.
// Otherwise returns err=ErrVote[
//		UnexpectedStep | InvalidIndex | InvalidAddress |
//		InvalidSignature | InvalidBlockHash | ConflictingVotes ]
// Duplicate votes return added=false, err=nil.
// Conflicting votes return added=*, err=ErrVoteConflictingVotes.
// NOTE: vote should not be mutated after adding.
// NOTE: VoteSet must not be nil
// NOTE: Vote must not be nil
func (voteSet *PrecommitSet) AddVote(vote *Vote) (added bool, err error) {
	if voteSet == nil {
		panic("AddVote() on nil VoteSet")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	return voteSet.addVote(vote)
}

// NOTE: Validates as much as possible before attempting to verify the signature.
func (voteSet *PrecommitSet) addVote(vote *Vote) (added bool, err error) {
	if vote == nil {
		return false, ErrVoteNil
	}
	valIndex := vote.ValidatorIndex
	valAddr := vote.ValidatorAddress
	blockKey := vote.BlockID.Key()

	// Ensure that validator index was set
	if valIndex < 0 {
		return false, errors.Wrap(ErrVoteInvalidValidatorIndex, "Index < 0")
	} else if len(valAddr) == 0 {
		return false, errors.Wrap(ErrVoteInvalidValidatorAddress, "Empty address")
	}

	// Make sure the step matches.
	if (vote.Height != voteSet.height) ||
		(vote.Round != voteSet.round) ||
		(vote.Type != PrecommitType) {
		return false, errors.Wrapf(ErrVoteUnexpectedStep, "Expected %d/%d/%d, but got %d/%d/%d",
			voteSet.height, voteSet.round, PrecommitType,
			vote.Height, vote.Round, vote.Type)
	}

	// Ensure that signer is a validator.
	lookupAddr, val := voteSet.valSet.GetByIndex(valIndex)
	if val == nil {
		return false, errors.Wrapf(ErrVoteInvalidValidatorIndex,
			"Cannot find validator %d in valSet of size %d", valIndex, voteSet.valSet.Size())
	}

	// Ensure that the signer has the right address.
	if !bytes.Equal(valAddr, lookupAddr) {
		return false, errors.Wrapf(ErrVoteInvalidValidatorAddress,
			"vote.ValidatorAddress (%X) does not match address (%X) for vote.ValidatorIndex (%d)\n"+
				"Ensure the genesis file is correct across all validators.",
			valAddr, lookupAddr, valIndex)
	}

	// If we already know of this vote, return false.
	if existing, ok := voteSet.getVote(valIndex, blockKey, vote.Timestamp); ok {
		if bytes.Equal(existing.TimestampSignature, vote.TimestampSignature) {
			return false, nil // duplicate
		}
		return false, errors.Wrapf(ErrVoteNonDeterministicSignature, "Existing vote: %v; New vote: %v", existing, vote)
	}

	// Check signature.
	if err := vote.Verify(VotePrefix(voteSet.chainID, voteSet.valSet.Hash()), val.PubKey); err != nil {
		return false, errors.Wrapf(err, "Failed to verify vote with ChainID %s and PubKey %s", voteSet.chainID, val.PubKey)
	}

	// Add vote and get conflicting vote if any.
	added, conflicting := voteSet.addVerifiedVote(vote, blockKey, val.VotingPower)
	if conflicting != nil {
		return added, NewConflictingVoteError(val, conflicting, vote)
	}
	if !added {
		panic("Expected to add non-conflicting vote")
	}
	return added, nil
}

// Returns (vote, true) if vote exists for valIndex and blockKey.
func (voteSet *PrecommitSet) getVote(valIndex int, blockKey string, timestamp time.Time) (vote *Vote, ok bool) {
	if existing := voteSet.votes[valIndex][CanonicalTime(timestamp)]; existing != nil && existing.BlockID.Key() == blockKey {
		return existing, true
	}
	if existing := voteSet.votesByBlock[blockKey].getByIndex(valIndex, timestamp); existing != nil {
		return existing, true
	}
	return nil, false
}

// Assumes signature is valid.
// If conflicting vote exists, returns it.
func (voteSet *PrecommitSet) addVerifiedVote(
	vote *Vote,
	blockKey string,
	votingPower int64,
) (added bool, conflicting *Vote) {
	valIndex := vote.ValidatorIndex
	timestamp := CanonicalTime(vote.Timestamp)

	// Already exists in voteSet.votes?
	for _, existing := range voteSet.votes[valIndex] {
		if vote.BlockID.Equals(existing.BlockID) {
			if existing.Timestamp.Equal(vote.Timestamp) {
				panic("addVerifiedVote does not expect duplicate votes")
			}
		} else {
			conflicting = existing
			break
		}
	}
	// Add to voteSet.votes and incr .sum
	voteSet.votes[valIndex][timestamp] = vote
	voteSet.votesBitArray.SetIndex(valIndex, true)
	if len(voteSet.votes[valIndex]) == 1 {
		voteSet.sum += votingPower
	}

	votesByBlock, ok := voteSet.votesByBlock[blockKey]
	if !ok {
		// Start tracking this blockKey
		votesByBlock = newBlockPrecommitVotes(false, voteSet.valSet.Size())
		voteSet.votesByBlock[blockKey] = votesByBlock
		// We'll add the vote in a bit.
	}

	// Before adding to votesByBlock, see if we'll exceed quorum
	origSum := votesByBlock.sum
	quorum := voteSet.valSet.TotalVotingPower()*2/3 + 1

	// Add vote to votesByBlock
	votesByBlock.addVerifiedVote(vote, votingPower)

	// If we just crossed the quorum threshold and have 2/3 majority...
	if origSum < quorum && quorum <= votesByBlock.sum {
		// Only consider the first quorum reached
		if voteSet.maj23 == nil {
			maj23BlockID := vote.BlockID
			voteSet.maj23 = &maj23BlockID
			// And also copy votes over to voteSet.votes
			for i, vote := range votesByBlock.votes {
				if vote != nil {
					voteSet.votes[i] = vote
				}
			}
		}
	}

	return true, conflicting
}

// If a peer claims that it has 2/3 majority for given blockKey, call this.
// NOTE: if there are too many peers, or too much peer churn,
// this can cause memory issues.
// TODO: implement ability to remove peers too
// NOTE: VoteSet must not be nil
func (voteSet *PrecommitSet) SetPeerMaj23(peerID P2PID, blockID BlockID) error {
	if voteSet == nil {
		panic("SetPeerMaj23() on nil VoteSet")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	blockKey := blockID.Key()

	// Make sure peer hasn't already told us something.
	if existing, ok := voteSet.peerMaj23s[peerID]; ok {
		if existing.Equals(blockID) {
			return nil // Nothing to do
		}
		return fmt.Errorf("setPeerMaj23: Received conflicting blockID from peer %v. Got %v, expected %v",
			peerID, blockID, existing)
	}
	voteSet.peerMaj23s[peerID] = blockID

	// Create .votesByBlock entry if needed.
	votesByBlock, ok := voteSet.votesByBlock[blockKey]
	if ok {
		if votesByBlock.peerMaj23 {
			return nil // Nothing to do
		}
		votesByBlock.peerMaj23 = true
		// No need to copy votes, already there.
	} else {
		votesByBlock = newBlockPrecommitVotes(true, voteSet.valSet.Size())
		voteSet.votesByBlock[blockKey] = votesByBlock
		// No need to copy votes, no votes to copy over.
	}
	return nil
}

// Implements VoteSetReader.
func (voteSet *PrecommitSet) BitArray() *bits.BitArray {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.votesBitArray.Copy()
}

func (voteSet *PrecommitSet) VotesByBlockID(blockID BlockID) []string {
	if voteSet == nil {
		return []string{}
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	votesByBlock, ok := voteSet.votesByBlock[blockID.Key()]
	if ok {
		votes := []string{}
		for _, valVotes := range votesByBlock.votes {
			for _, v := range valVotes {
				votes = append(votes, PrecommitIdentifier(v.ValidatorIndex, v.Timestamp))
			}
		}
		return votes
	}
	return []string{}
}

// GetByIndex returns all precommit votes from a validator index as a map with timestamp
// as the key
func (voteSet *PrecommitSet) GetVoteTimestamps(valIndex int) []time.Time {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	votes := make([]time.Time, len(voteSet.votes[valIndex]))
	i := 0
	for _, vote := range voteSet.votes[valIndex] {
		votes[i] = vote.Timestamp
		i++
	}
	return votes
}

// GetByIndex returns all precommit votes from a validator index as a map with timestamp
// as the key
func (voteSet *PrecommitSet) GetByIndex(valIndex int, timestamp time.Time) *Vote {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	if v, ok := voteSet.votes[valIndex][CanonicalTime(timestamp)]; ok {
		return v
	}
	return nil
}

func (voteSet *PrecommitSet) HasTwoThirdsMajority() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.maj23 != nil
}

// Implements VoteSetReader.
func (voteSet *PrecommitSet) IsCommit() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.maj23 != nil
}

func (voteSet *PrecommitSet) HasTwoThirdsAny() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.sum > voteSet.valSet.TotalVotingPower()*2/3
}

func (voteSet *PrecommitSet) HasAll() bool {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.sum == voteSet.valSet.TotalVotingPower()
}

// If there was a +2/3 majority for blockID, return blockID and true.
// Else, return the empty BlockID{} and false.
func (voteSet *PrecommitSet) TwoThirdsMajority() (blockID BlockID, ok bool) {
	if voteSet == nil {
		return BlockID{}, false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	if voteSet.maj23 != nil {
		return *voteSet.maj23, true
	}
	return BlockID{}, false
}

//--------------------------------------------------------------------------------
// Strings and JSON

func (voteSet *PrecommitSet) String() string {
	if voteSet == nil {
		return "nil-VoteSet"
	}
	return voteSet.StringIndented("")
}

func (voteSet *PrecommitSet) StringIndented(indent string) string {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	voteStrings := make([]string, len(voteSet.votes))
	for i, vote := range voteSet.votes {
		if vote == nil {
			voteStrings[i] = nilVoteStr
		} else {
			duplicateTimestampVotesStr := []string{}
			for _, duplicateTimestampVotes := range vote {
				duplicateTimestampVotesStr = append(duplicateTimestampVotesStr, duplicateTimestampVotes.String())
			}
			voteStrings[i] = strings.Join(duplicateTimestampVotesStr, "\n"+indent+"  ")
		}
	}
	return fmt.Sprintf(`VoteSet{
%s  H:%v R:%v T:%v
%s  %v
%s  %v
%s  %v
%s}`,
		indent, voteSet.height, voteSet.round, PrecommitType,
		indent, strings.Join(voteStrings, "\n"+indent+"  "),
		indent, voteSet.votesBitArray,
		indent, voteSet.peerMaj23s,
		indent)
}

// Marshal the VoteSet to JSON. Same as String(), just in JSON,
// and without the height/round/signedMsgType (since its already included in the votes).
func (voteSet *PrecommitSet) MarshalJSON() ([]byte, error) {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return cdc.MarshalJSON(VoteSetJSON{
		voteSet.voteStrings(),
		voteSet.bitArrayString(),
		voteSet.peerMaj23s,
	})
}

// Return the bit-array of votes including
// the fraction of power that has voted like:
// "BA{29:xx__x__x_x___x__x_______xxx__} 856/1304 = 0.66"
func (voteSet *PrecommitSet) BitArrayString() string {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.bitArrayString()
}

func (voteSet *PrecommitSet) bitArrayString() string {
	bAString := voteSet.votesBitArray.String()
	voted, total, fracVoted := voteSet.sumTotalFrac()
	return fmt.Sprintf("%s %d/%d = %.2f", bAString, voted, total, fracVoted)
}

// Returns a list of votes compressed to more readable strings.
func (voteSet *PrecommitSet) VoteStrings() []string {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.voteStrings()
}

func (voteSet *PrecommitSet) voteStrings() []string {
	voteStrings := make([]string, len(voteSet.votes))
	for i, vote := range voteSet.votes {
		if vote == nil {
			voteStrings[i] = nilVoteStr
		} else {
			duplicateTimestampVotesStr := []string{}
			for _, duplicateTimestampVotes := range vote {
				duplicateTimestampVotesStr = append(duplicateTimestampVotesStr, duplicateTimestampVotes.String())
			}
			voteStrings[i] = strings.Join(duplicateTimestampVotesStr, "\n"+"  ")
		}
	}
	return voteStrings
}

func (voteSet *PrecommitSet) StringShort() string {
	if voteSet == nil {
		return "nil-VoteSet"
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	_, _, frac := voteSet.sumTotalFrac()
	return fmt.Sprintf(`VoteSet{H:%v R:%v T:%v +2/3:%v(%v) %v %v}`,
		voteSet.height, voteSet.round, PrecommitType, voteSet.maj23, frac, voteSet.votesBitArray, voteSet.peerMaj23s)
}

// return the PrecommitVoteSet voted, the total, and the fraction
func (voteSet *PrecommitSet) sumTotalFrac() (int64, int64, float64) {
	voted, total := voteSet.sum, voteSet.valSet.TotalVotingPower()
	fracVoted := float64(voted) / float64(total)
	return voted, total, fracVoted
}

//--------------------------------------------------------------------------------
// Commit

// MakeCommit constructs a Commit from the VoteSet. It only includes precommits
// for the block, which has 2/3+ majority, and nil.
//
// Panics if the vote type is not PrecommitType or if there's no +2/3 votes for
// a single block.
func (voteSet *PrecommitSet) MakeCommit() *Commit {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	// Make sure we have a 2/3 majority
	if voteSet.maj23 == nil {
		panic("Cannot MakeCommit() unless a blockhash has +2/3")
	}

	// For every validator, get the precommit
	commitSigs := make([][]CommitSig, voteSet.valSet.Size())
	for i, votes := range voteSet.votes {
		commitSigs[i] = make([]CommitSig, len(votes))
		j := 0
		for _, v := range votes {
			commitSig := v.CommitSig()
			// if block ID exists but doesn't match, exclude sig
			if commitSig.ForBlock() && !v.BlockID.Equals(*voteSet.maj23) {
				commitSig = NewCommitSigAbsent()
			}
			commitSigs[i][j] = commitSig
			j++
		}
	}

	return NewCommit(voteSet.GetHeight(), voteSet.GetRound(), *voteSet.maj23, commitSigs)
}

//--------------------------------------------------------------------------------

/*
	Votes for a particular block
	There are two ways a *blockVotes gets created for a blockKey.
	1. first (non-conflicting) vote of a validator w/ blockKey (peerMaj23=false)
	2. A peer claims to have a 2/3 majority w/ blockKey (peerMaj23=true)
*/
type blockPrecommitVotes struct {
	peerMaj23 bool                     // peer claims to have maj23
	bitArray  *bits.BitArray           // valIndex -> hasVote?
	votes     map[int]map[string]*Vote // valIndex -> *Vote
	sum       int64                    // vote sum
}

func newBlockPrecommitVotes(peerMaj23 bool, numValidators int) *blockPrecommitVotes {
	blockPrecommitVotes := &blockPrecommitVotes{
		peerMaj23: peerMaj23,
		bitArray:  bits.NewBitArray(numValidators),
		votes:     make(map[int]map[string]*Vote, numValidators),
		sum:       0,
	}

	// Initialise nest map
	for index := 0; index < numValidators; index++ {
		blockPrecommitVotes.votes[index] = map[string]*Vote{}
	}

	return blockPrecommitVotes
}

func (vs *blockPrecommitVotes) addVerifiedVote(vote *Vote, votingPower int64) {
	valIndex := vote.ValidatorIndex
	timestamp := CanonicalTime(vote.Timestamp)
	if existing := vs.votes[valIndex][timestamp]; existing == nil {
		vs.bitArray.SetIndex(valIndex, true)
		vs.votes[valIndex][timestamp] = vote
		// Only count the validator voting power for one vote
		if len(vs.votes[valIndex]) == 1 {
			vs.sum += votingPower
		}
	}
}

func (vs *blockPrecommitVotes) getByIndex(index int, timestamp time.Time) *Vote {
	if vs == nil {
		return nil
	}
	return vs.votes[index][CanonicalTime(timestamp)]
}
