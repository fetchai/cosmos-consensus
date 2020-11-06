package types

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/crypto"
	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	tmproto "github.com/tendermint/tendermint/proto/types"
)

// BlockIDFlag indicates which BlockID the signature is for.
type BlockIDFlag byte

const (
	// BlockIDFlagAbsent - no vote was received from a validator.
	BlockIDFlagAbsent BlockIDFlag = iota + 1
	// BlockIDFlagCommit - voted for the Commit.BlockID.
	BlockIDFlagCommit
	// BlockIDFlagNil - voted for nil.
	BlockIDFlagNil
)

// CommitSigVote is a part of the Vote included in a VotesCommit and contains all signatures required
// to verify the contents in the vote. This is not included in blocks but only saved locally in the node
// block store as the votes seen for each block
type CommitSigVote struct {
	BlockIDFlag        BlockIDFlag `json:"block_id_flag"`
	ValidatorAddress   Address     `json:"validator_address"`
	Timestamp          time.Time   `json:"timestamp"`
	Signature          []byte      `json:"signature"`
	TimestampSignature []byte      `json:"timestamp_signature"`
}

// NewCommitSigVoteForBlock returns new CommitSigVote with BlockIDFlagCommit.
func NewCommitSigVoteForBlock(signature []byte, valAddr Address, ts time.Time, timestampSig []byte) CommitSigVote {
	return CommitSigVote{
		BlockIDFlag:        BlockIDFlagCommit,
		ValidatorAddress:   valAddr,
		Timestamp:          ts,
		Signature:          signature,
		TimestampSignature: timestampSig,
	}
}

// NewCommitSigVoteAbsent returns new CommitigVote with BlockIDFlagAbsent. Other
// fields are all empty.
func NewCommitSigVoteAbsent() CommitSigVote {
	return CommitSigVote{
		BlockIDFlag: BlockIDFlagAbsent,
	}
}

// ForBlock returns true if CommitSig is for the block.
func (cs CommitSigVote) ForBlock() bool {
	return cs.BlockIDFlag == BlockIDFlagCommit
}

// Absent returns true if CommitSig is absent.
func (cs CommitSigVote) Absent() bool {
	return cs.BlockIDFlag == BlockIDFlagAbsent
}

func (cs CommitSigVote) String() string {
	return fmt.Sprintf("CommitSigVote{%X by %X on %v @ %s %X}",
		tmbytes.Fingerprint(cs.Signature),
		tmbytes.Fingerprint(cs.ValidatorAddress),
		cs.BlockIDFlag,
		CanonicalTime(cs.Timestamp),
		cs.TimestampSignature)
}

// BlockID returns the Commit's BlockID if CommitSig indicates signing,
// otherwise - empty BlockID.
func (cs CommitSigVote) BlockID(commitBlockID BlockID) BlockID {
	var blockID BlockID
	switch cs.BlockIDFlag {
	case BlockIDFlagAbsent:
		blockID = BlockID{}
	case BlockIDFlagCommit:
		blockID = commitBlockID
	case BlockIDFlagNil:
		blockID = BlockID{}
	default:
		panic(fmt.Sprintf("Unknown BlockIDFlag: %v", cs.BlockIDFlag))
	}
	return blockID
}

// ValidateBasic performs basic validation.
func (cs CommitSigVote) ValidateBasic() error {
	switch cs.BlockIDFlag {
	case BlockIDFlagAbsent:
	case BlockIDFlagCommit:
	case BlockIDFlagNil:
	default:
		return fmt.Errorf("unknown BlockIDFlag: %v", cs.BlockIDFlag)
	}

	switch cs.BlockIDFlag {
	case BlockIDFlagAbsent:
		if len(cs.ValidatorAddress) != 0 {
			return errors.New("validator address is present")
		}
		if !cs.Timestamp.IsZero() {
			return errors.New("time is present")
		}
		if len(cs.Signature) != 0 {
			return errors.New("signature is present")
		}
	default:
		if len(cs.ValidatorAddress) != crypto.AddressSize {
			return fmt.Errorf("expected ValidatorAddress size to be %d bytes, got %d bytes",
				crypto.AddressSize,
				len(cs.ValidatorAddress),
			)
		}
		// NOTE: Timestamp validation is subtle and handled elsewhere.
		if len(cs.Signature) == 0 {
			return errors.New("signature is missing")
		}
		if len(cs.Signature) > MaxSignatureSize {
			return fmt.Errorf("signature is too big (max: %d)", MaxSignatureSize)
		}
		if len(cs.TimestampSignature) == 0 {
			return fmt.Errorf("timestamp signature is missing")
		}
		if len(cs.TimestampSignature) > MaxSignatureSize {
			return fmt.Errorf("timestamp signature is too big (max: %d)", MaxSignatureSize)
		}
	}

	return nil
}

//---------------------------------------------------------------------------

// CommitSigBlock is a part of the Vote included in a BlockCommit and is the information
// stored for each validator in the block. Most importantly it omits the signatures in the original
// vote messages
type CommitSigBlock struct {
	BlockIDFlag      BlockIDFlag `json:"block_id_flag"`
	ValidatorAddress Address     `json:"validator_address"`
	Timestamp        time.Time   `json:"timestamp"`
}

// NewCommitSigBlockForBlock returns new CommitSigBlock with BlockIDFlagCommit.
func NewCommitSigBlockForBlock(valAddr Address, ts time.Time) CommitSigBlock {
	return CommitSigBlock{
		BlockIDFlag:      BlockIDFlagCommit,
		ValidatorAddress: valAddr,
		Timestamp:        ts,
	}
}

// NewCommitSigBlockAbsent returns new CommitSigBlock with BlockIDFlagAbsent. Other
// fields are all empty.
func NewCommitSigBlockAbsent() CommitSigBlock {
	return CommitSigBlock{
		BlockIDFlag: BlockIDFlagAbsent,
	}
}

// ForBlock returns true if CommitSig is for the block.
func (cs CommitSigBlock) ForBlock() bool {
	return cs.BlockIDFlag == BlockIDFlagCommit
}

// Absent returns true if CommitSig is absent.
func (cs CommitSigBlock) Absent() bool {
	return cs.BlockIDFlag == BlockIDFlagAbsent
}

func (cs CommitSigBlock) String() string {
	return fmt.Sprintf("CommitSig{%X on %v @ %s}",
		tmbytes.Fingerprint(cs.ValidatorAddress),
		cs.BlockIDFlag,
		CanonicalTime(cs.Timestamp))
}

// BlockID returns the Commit's BlockID if CommitSig indicates signing,
// otherwise - empty BlockID.
func (cs CommitSigBlock) BlockID(commitBlockID BlockID) BlockID {
	var blockID BlockID
	switch cs.BlockIDFlag {
	case BlockIDFlagAbsent:
		blockID = BlockID{}
	case BlockIDFlagCommit:
		blockID = commitBlockID
	case BlockIDFlagNil:
		blockID = BlockID{}
	default:
		panic(fmt.Sprintf("Unknown BlockIDFlag: %v", cs.BlockIDFlag))
	}
	return blockID
}

// ValidateBasic performs basic validation.
func (cs CommitSigBlock) ValidateBasic() error {
	switch cs.BlockIDFlag {
	case BlockIDFlagAbsent:
	case BlockIDFlagCommit:
	case BlockIDFlagNil:
	default:
		return fmt.Errorf("unknown BlockIDFlag: %v", cs.BlockIDFlag)
	}

	switch cs.BlockIDFlag {
	case BlockIDFlagAbsent:
		if len(cs.ValidatorAddress) != 0 {
			return errors.New("validator address is present")
		}
		if !cs.Timestamp.IsZero() {
			return errors.New("time is present")
		}
	default:
		if len(cs.ValidatorAddress) != crypto.AddressSize {
			return fmt.Errorf("expected ValidatorAddress size to be %d bytes, got %d bytes",
				crypto.AddressSize,
				len(cs.ValidatorAddress),
			)
		}
	}

	return nil
}

// ToProto converts CommitSig to protobuf
func (cs *CommitSigBlock) ToProto() *tmproto.CommitSig {
	if cs == nil {
		return nil
	}

	return &tmproto.CommitSig{
		BlockIdFlag:      tmproto.BlockIDFlag(cs.BlockIDFlag),
		ValidatorAddress: cs.ValidatorAddress,
		Timestamp:        cs.Timestamp,
	}
}

// FromProto sets a protobuf CommitSig to the given pointer.
// It returns an error if the CommitSig is invalid.
func (cs *CommitSigBlock) FromProto(csp tmproto.CommitSig) error {

	cs.BlockIDFlag = BlockIDFlag(csp.BlockIdFlag)
	cs.ValidatorAddress = csp.ValidatorAddress
	cs.Timestamp = csp.Timestamp

	return cs.ValidateBasic()
}
