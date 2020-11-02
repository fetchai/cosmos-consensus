package types

import (
	"time"

	"github.com/pkg/errors"
)

func MakeCommit(blockID BlockID, height int64, round int,
	voteSet *PrecommitSet, validators []PrivValidator, now time.Time) (*Commit, error) {

	// all sign
	for i := 0; i < len(validators); i++ {
		pubKey, err := validators[i].GetPubKey()
		if err != nil {
			return nil, errors.Wrap(err, "can't get pubkey")
		}
		vote := &Vote{
			ValidatorAddress: pubKey.Address(),
			ValidatorIndex:   i,
			Height:           height,
			Round:            round,
			Type:             PrecommitType,
			BlockID:          blockID,
			Timestamp:        now,
		}

		_, err = signAddVote(validators[i], vote, voteSet)
		if err != nil {
			return nil, err
		}
	}

	return voteSet.MakeCommit(), nil
}

func signAddVote(privVal PrivValidator, vote *Vote, voteSet VoteSet) (signed bool, err error) {
	err = privVal.SignVote(VotePrefix(voteSet.ChainID(), voteSet.ValidatorSetHash()), vote)
	if err != nil {
		return false, err
	}
	return voteSet.AddVote(vote)
}

func MakeVote(
	height int64,
	blockID BlockID,
	valSet *ValidatorSet,
	privVal PrivValidator,
	chainID string,
	now time.Time,
) (*Vote, error) {
	pubKey, err := privVal.GetPubKey()
	if err != nil {
		return nil, errors.Wrap(err, "can't get pubkey")
	}
	addr := pubKey.Address()
	idx, _ := valSet.GetByAddress(addr)
	vote := &Vote{
		ValidatorAddress: addr,
		ValidatorIndex:   idx,
		Height:           height,
		Round:            0,
		Timestamp:        now,
		Type:             PrecommitType,
		BlockID:          blockID,
	}
	if err := privVal.SignVote(VotePrefix(chainID, valSet.Hash()), vote); err != nil {
		return nil, err
	}
	return vote, nil
}

// MakeBlock returns a new block with an empty header, except what can be
// computed from itself.
// It populates the same set of fields validated by ValidateBasic.
func MakeBlock(height int64, txs []Tx, lastCommit *Commit, evidence []Evidence) *Block {
	// Copy commit and remove timestamp signatures from commit
	commitPtr := lastCommit
	if commitPtr != nil {
		commit := *lastCommit
		commit.Signatures = make([][]CommitSig, len(lastCommit.Signatures))
		for index := range lastCommit.Signatures {
			commit.Signatures[index] = []CommitSig{NewCommitSigAbsent()}
			if len(lastCommit.Signatures[index]) > 0 {
				commit.Signatures[index][0] = lastCommit.Signatures[index][0]
				commit.Signatures[index][0].TimestampSignature = nil
			}
		}
		commitPtr = &commit
	}

	block := &Block{
		Header: Header{
			Height:  height,
			Entropy: *EmptyBlockEntropy(),
		},
		Data: Data{
			Txs: txs,
		},
		Evidence:   EvidenceData{Evidence: evidence},
		LastCommit: commitPtr,
	}
	block.fillHeader()
	return block
}
