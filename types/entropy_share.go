package types

import (
	"fmt"

	"github.com/tendermint/tendermint/crypto"
)

// For event switch in entropy generator
const (
	EventComputedEntropy      = "EventComputedEntropy"
	MaxEntropyShareSize       = 256
	MaxThresholdSignatureSize = 256
	GenesisHeight             = int64(0)
)

type ThresholdSignature = []byte

//-----------------------------------------------------------------------------

type ComputedEntropy struct {
	Height         int64
	GroupSignature ThresholdSignature
	Enabled        bool
}

func NewComputedEntropy(height int64, sig ThresholdSignature, enabled bool) *ComputedEntropy {
	return &ComputedEntropy{
		Height:         height,
		GroupSignature: sig,
		Enabled:        enabled,
	}
}

func (ce *ComputedEntropy) IsEmpty() bool {
	return ce.GroupSignature == nil || len(ce.GroupSignature) == 0
}

// ValidateBasic performs basic validation.
func (ce *ComputedEntropy) ValidateBasic() error {
	if ce.Height <= GenesisHeight {
		return fmt.Errorf("invalid Height")
	}

	if len(ce.GroupSignature) > MaxThresholdSignatureSize {
		return fmt.Errorf("expected GroupSignature size be max %d bytes, got %d bytes",
			MaxThresholdSignatureSize,
			len(ce.GroupSignature),
		)
	}

	return nil
}

// String returns a string representation of the PeerRoundState
func (ce *ComputedEntropy) String() string {
	return ce.StringIndented("")
}

// StringIndented returns a string representation of the PeerRoundState
func (ce *ComputedEntropy) StringIndented(indent string) string {
	return fmt.Sprintf(`ComputedEntropy{
%s  %v/%v
%s}`,
		indent, ce.Height, ce.GroupSignature,
		indent)
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
