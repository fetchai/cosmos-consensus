package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/libs/bits"
	tmtime "github.com/tendermint/tendermint/types/time"
)

func TestCommit(t *testing.T) {
	lastID := makeBlockIDRandom()
	h := int64(3)
	voteSet, _, vals := randPrecommitSet(h-1, 1, 10, 1)
	commit, err := MakeCommit(lastID, h-1, 1, voteSet, vals, time.Now())
	require.NoError(t, err)

	assert.Equal(t, h-1, commit.Height)
	assert.Equal(t, 1, commit.Round)
	assert.Equal(t, PrecommitType, SignedMsgType(commit.Type()))
	if commit.Size() <= 0 {
		t.Fatalf("commit %v has a zero or negative size: %d", commit, commit.Size())
	}

	require.NotNil(t, commit.BitArray())
	assert.Equal(t, bits.NewBitArray(10).Size(), commit.BitArray().Size())

	vote := voteSet.GetByIndex(0, voteSet.GetVoteTimestamps(0)[0])
	assert.Equal(t, vote, commit.GetByIndex(0))
	assert.True(t, commit.IsCommit())
}

func TestVotesCommitValidateBasic(t *testing.T) {
	testCases := []struct {
		testName       string
		malleateCommit func(*VotesCommit)
		expectErr      bool
	}{
		{"Random Commit", func(com *VotesCommit) {}, false},
		{"Incorrect signature", func(com *VotesCommit) { com.Signatures[0][0].Signature = []byte{0} }, false},
		{"Incorrect height", func(com *VotesCommit) { com.Height = int64(-100) }, true},
		{"Incorrect round", func(com *VotesCommit) { com.Round = -100 }, true},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			com := randVotesCommit(time.Now())
			tc.malleateCommit(com)
			assert.Equal(t, tc.expectErr, com.ValidateBasic() != nil, "Validate Basic had an unexpected result")
		})
	}
}

func TestCommitToVoteSet(t *testing.T) {
	lastID := makeBlockIDRandom()
	h := int64(3)

	voteSet, valSet, vals := randPrecommitSet(h-1, 1, 10, 1)
	commit, err := MakeCommit(lastID, h-1, 1, voteSet, vals, time.Now())
	assert.NoError(t, err)

	chainID := voteSet.ChainID()
	voteSet2, _ := CommitToVoteSet(chainID, commit, valSet)

	for i := 0; i < len(vals); i++ {
		vote1 := voteSet.GetByIndex(i, voteSet.GetVoteTimestamps(i)[0])
		vote2 := voteSet2.GetByIndex(i, voteSet2.GetVoteTimestamps(i)[0])
		vote3 := commit.GetVote(i, 0)

		vote1bz := cdc.MustMarshalBinaryBare(vote1)
		vote2bz := cdc.MustMarshalBinaryBare(vote2)
		vote3bz := cdc.MustMarshalBinaryBare(vote3)
		assert.Equal(t, vote1bz, vote2bz)
		assert.Equal(t, vote1bz, vote3bz)
	}
}

func TestCommitToVoteSetWithVotesForNilBlock(t *testing.T) {
	blockID := makeBlockID([]byte("blockhash"), 1000, []byte("partshash"))

	const (
		height = int64(3)
		round  = 0
	)

	type commitVoteTest struct {
		blockIDs      []BlockID
		numVotes      []int // must sum to numValidators
		numValidators int
		valid         bool
	}

	testCases := []commitVoteTest{
		{[]BlockID{blockID, {}}, []int{67, 33}, 100, true},
	}

	for _, tc := range testCases {
		voteSet, valSet, vals := randPrecommitSet(height-1, round, tc.numValidators, 1)

		vi := 0
		for n := range tc.blockIDs {
			for i := 0; i < tc.numVotes[n]; i++ {
				pubKey, err := vals[vi].GetPubKey()
				require.NoError(t, err)
				vote := &Vote{
					ValidatorAddress: pubKey.Address(),
					ValidatorIndex:   vi,
					Height:           height - 1,
					Round:            round,
					Type:             PrecommitType,
					BlockID:          tc.blockIDs[n],
					Timestamp:        tmtime.Now(),
				}

				added, err := signAddVote(vals[vi], vote, voteSet)
				assert.NoError(t, err)
				assert.True(t, added)

				vi++
			}
		}

		if tc.valid {
			commit := voteSet.MakeBlockCommit() // panics without > 2/3 valid votes
			assert.NotNil(t, commit)
			err := valSet.VerifyCommit(voteSet.ChainID(), blockID, height-1, commit)
			assert.Nil(t, err)
		} else {
			assert.Panics(t, func() { voteSet.MakeBlockCommit() })
		}
	}
}

func randVotesCommit(now time.Time) *VotesCommit {
	lastID := makeBlockIDRandom()
	h := int64(3)
	voteSet, _, vals := randPrecommitSet(h-1, 1, 10, 1)
	commit, err := MakeCommit(lastID, h-1, 1, voteSet, vals, now)
	if err != nil {
		panic(err)
	}
	return commit
}
