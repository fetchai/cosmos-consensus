package types

import (
	"errors"
	"fmt"
	"github.com/tendermint/tendermint/crypto"
)

var (
	// TODO: Check this is ok with mcl
	MaxEntropyShareSize = 64
	GenesisHeight = int64(0)
)
//-----------------------------------------------------------------------------

// PeerRoundState contains the known state of a peer.
// NOTE: Read-only when returned by PeerState.GetRoundState().
type EntropyShare struct {
	Height int64           `json:"height"`
	SignerAddress  crypto.Address  `json:"signer"`
	SignatureShare []byte  `json:"signature"`
}

// ValidateBasic performs basic validation.
func (entropy *EntropyShare) ValidateBasic() error {
	if entropy.Height < GenesisHeight + 1{
		return errors.New("invalid Height")
	}

	if len(entropy.SignerAddress) != crypto.AddressSize {
		return fmt.Errorf("expected ValidatorAddress size to be %d bytes, got %d bytes",
			crypto.AddressSize,
			len(entropy.SignerAddress),
		)
	}
	if len(entropy.SignatureShare) == 0 {
		return errors.New("signature is missing")
	}
	if len(entropy.SignatureShare) > MaxEntropyShareSize {
		return fmt.Errorf("signature is too big (max: %d)", MaxEntropyShareSize)
	}
	return nil
}

// String returns a string representation of the PeerRoundState
func (entropy EntropyShare) String() string {
	return entropy.StringIndented("")
}

// StringIndented returns a string representation of the PeerRoundState
func (entropy EntropyShare) StringIndented(indent string) string {
	return fmt.Sprintf(`EntropySignatureShare{
%s  %v/%v/%v
%s}`,
		indent, entropy.Height, entropy.SignerAddress, entropy.SignatureShare,
		indent)
}

//-----------------------------------------------------------
// These methods are for Protobuf Compatibility

// Size returns the size of the amino encoding, in bytes.
func (entropy *EntropyShare) Size() int {
	bs, _ := entropy.Marshal()
	return len(bs)
}

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
