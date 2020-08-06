package types

import (
	"bytes"
	"fmt"

	"github.com/tendermint/tendermint/crypto"
)

// For event switch in entropy generator
const (
	EventComputedEntropy      = "EventComputedEntropy"
	MaxEntropyShareSize       = 500
	MaxThresholdSignatureSize = 256
	GenesisHeight             = int64(0)
)

type ThresholdSignature = []byte

//-----------------------------------------------------------------------------

// BlockEntropy struct for entropy in block
type BlockEntropy struct {
	GroupSignature ThresholdSignature `json:"group_signature"`
	Round          int64              `json:"round"`
	AeonLength     int64              `json:"aeon_length"`
	DKGID          int64              `json:"dkg_id"`
	NextAeonStart  int64              `json:"next_aeon_start`
}

// EmptyBlockEntropy for constructing BlockEntropy for empty group signature
func EmptyBlockEntropy(nextAeonStart int64) *BlockEntropy {
	return &BlockEntropy{
		GroupSignature: []byte{},
		Round:          -1,
		AeonLength:     -1,
		DKGID:          -1,
		NextAeonStart:  nextAeonStart,
	}
}

// Function to test if a block entropy is empty
func IsEmptyBlockEntropy(entropy *BlockEntropy) bool {
	return len(entropy.GroupSignature) == 0
}

// NewBlockEntropy for constructing BlockEntropy
func NewBlockEntropy(sig ThresholdSignature, round int64, aeonLength int64, dkgID int64, nextAeonStart int64) *BlockEntropy {
	return &BlockEntropy{
		GroupSignature: sig,
		Round:          round,
		AeonLength:     aeonLength,
		DKGID:          dkgID,
		NextAeonStart:  nextAeonStart,
	}
}

// Equal compares two block entropies and returns if they are identical
func (blockEntropy *BlockEntropy) Equal(anotherEntropy *BlockEntropy) bool {
	return bytes.Equal(blockEntropy.GroupSignature, anotherEntropy.GroupSignature) &&
		blockEntropy.Round == anotherEntropy.Round &&
		blockEntropy.AeonLength == anotherEntropy.AeonLength &&
		blockEntropy.DKGID == anotherEntropy.DKGID &&
		blockEntropy.NextAeonStart == anotherEntropy.NextAeonStart
}

// ValidateBasic performs basic validation on block entropy
func (blockEntropy *BlockEntropy) ValidateBasic() error {
	// If entropy is empty then all other values should be -1
	if len(blockEntropy.GroupSignature) == 0 {
		if blockEntropy.Round != -1 || blockEntropy.AeonLength != -1 || blockEntropy.DKGID != -1 {
			return fmt.Errorf("expected EmptyBlockEntropy, got: round %d, aeon length %v, dkg id %v",
				blockEntropy.Round, blockEntropy.AeonLength, blockEntropy.DKGID)
		}
		return nil
	}

	if len(blockEntropy.GroupSignature) > MaxThresholdSignatureSize {
		return fmt.Errorf("expected GroupSignature size be max %d bytes, got %d bytes",
			MaxThresholdSignatureSize,
			len(blockEntropy.GroupSignature),
		)
	}
	if blockEntropy.Round < 0 {
		return fmt.Errorf("expected Round >= 0, got %d", blockEntropy.Round)
	}
	if blockEntropy.AeonLength <= 0 {
		return fmt.Errorf("expected AeonLength > 0, got %d", blockEntropy.AeonLength)
	}
	if blockEntropy.DKGID < 0 {
		return fmt.Errorf("expected DKG ID >= 0, got %d", blockEntropy.DKGID)
	}
	return nil
}

// String returns a string representation of the BlockEntropy
func (blockEntropy *BlockEntropy) String() string {
	return blockEntropy.StringIndented("")
}

// StringIndented returns a string representation of the BlockEntropy
func (blockEntropy *BlockEntropy) StringIndented(indent string) string {
	return fmt.Sprintf(`BlockEntropy{
%s  Round/AeonLength: %v/%v
%s  DKGID:			  %v 
%s  NextAeonStart:    %v
%s  GroupSignature:	  %v
%s}`,
		indent, blockEntropy.Round, blockEntropy.AeonLength,
		indent, blockEntropy.DKGID,
		indent, blockEntropy.NextAeonStart,
		indent, blockEntropy.GroupSignature,
		indent)
}

//-----------------------------------------------------------------------------

// ChannelEntropy struct for sending entropy from entropy generator to consensus
type ChannelEntropy struct {
	Height        int64
	Entropy       BlockEntropy
	Enabled       bool
	ValidatorHash []byte
}

// NewChannelEntropy for constructing ChannelEntropy
func NewChannelEntropy(height int64, entropy BlockEntropy, enabled bool, validatorHash []byte) *ChannelEntropy {
	return &ChannelEntropy{
		Height:        height,
		Entropy:       entropy,
		Enabled:       enabled,
		ValidatorHash: validatorHash,
	}
}

// ValidateBasic performs basic validation.
func (ce *ChannelEntropy) ValidateBasic() error {
	if ce.Height <= GenesisHeight {
		return fmt.Errorf("invalid Height")
	}

	err := ce.Entropy.ValidateBasic()
	if err != nil {
		return err
	}

	return nil
}

//-----------------------------------------------------------------------------
// Wrappers for signing entropy message

type CanonicalEntropyShare struct {
	Height         int64
	SignerAddress  crypto.Address
	SignatureShare string
	ChainID        string
}

func CanonicalizeEntropyShare(chainID string, entropy *EntropyShare) CanonicalEntropyShare {
	return CanonicalEntropyShare{
		Height:         entropy.Height,
		SignerAddress:  entropy.SignerAddress,
		SignatureShare: entropy.SignatureShare,
		ChainID:        chainID,
	}
}

//-----------------------------------------------------------------------------

type EntropyShare struct {
	Height         int64          `json:"height"`
	SignerAddress  crypto.Address `json:"signer"`
	SignatureShare string         `json:"entropy_signature"`
	Signature      []byte         `json:"signature"`
}

// ValidateBasic performs basic validation.
func (entropy *EntropyShare) ValidateBasic() error {
	if entropy.Height < GenesisHeight+1 {
		return fmt.Errorf("invalid Height")
	}

	if len(entropy.SignerAddress) != crypto.AddressSize {
		return fmt.Errorf("expected ValidatorAddress size to be %d bytes, got %d bytes",
			crypto.AddressSize,
			len(entropy.SignerAddress),
		)
	}
	if len(entropy.SignatureShare) == 0 || len(entropy.SignatureShare) > MaxEntropyShareSize {
		return fmt.Errorf("expected SignatureShare size be max %d bytes, got %d bytes",
			MaxEntropyShareSize,
			len(entropy.SignatureShare),
		)
	}
	if len(entropy.Signature) == 0 || len(entropy.Signature) > MaxThresholdSignatureSize {
		return fmt.Errorf("expected Signature size be max %d bytes, got %d bytes",
			MaxThresholdSignatureSize,
			len(entropy.Signature),
		)
	}
	return nil
}

// String returns a string representation of EntropyShare
func (entropy EntropyShare) String() string {
	return entropy.StringIndented("")
}

// StringIndented returns a string representation of the EntropyShare
func (entropy EntropyShare) StringIndented(indent string) string {
	return fmt.Sprintf(`EntropySignatureShare{
%s  %v/%v/%v%v
%s}`,
		indent, entropy.Height, entropy.SignerAddress, entropy.SignatureShare, entropy.Signature,
		indent)
}

func (entropy EntropyShare) Copy() EntropyShare {
	return EntropyShare{
		Height:         entropy.Height,
		SignerAddress:  entropy.SignerAddress,
		SignatureShare: entropy.SignatureShare,
		Signature:      entropy.Signature,
	}
}

//-----------------------------------------------------------
// These methods are for Protobuf Compatibility

// Marshal returns the amino encoding.
func (entropy *EntropyShare) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryBare(entropy)
}

// MarshalTo calls Marshal and copies to the given buffer.
func (entropy *EntropyShare) MarshalTo(data []byte) (int, error) {
	bs, err := entropy.Marshal()
	if err != nil {
		return -1, err
	}
	return copy(data, bs), nil
}

// Unmarshal deserializes from amino encoded form.
func (entropy *EntropyShare) Unmarshal(bs []byte) error {
	return cdc.UnmarshalBinaryBare(bs, entropy)
}

// For signing with private key
func (entropy *EntropyShare) SignBytes(chainID string) []byte {
	bz, err := cdc.MarshalBinaryLengthPrefixed(CanonicalizeEntropyShare(chainID, entropy))
	if err != nil {
		panic(err)
	}
	return bz
}
