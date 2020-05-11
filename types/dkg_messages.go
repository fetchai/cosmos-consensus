package types

import (
	"fmt"

	"github.com/tendermint/tendermint/crypto"
)

// DKGMessageType are message types allowed in DKG
type DKGMessageType uint16

const (
	DKGShare DKGMessageType = iota
	DKGCoefficient
	DKGComplaint
	DKGComplaintAnswer
	DKGQualCoefficient
	DKGQualComplaint
	DKGReconstructionShare
	DKGDryRun

	MaxDKGDataSize = 32000 // Max value calculated for committee size of 200
)

// DKGMessage contains DKGData for a particular phase of the DKG
type DKGMessage struct {
	Type         DKGMessageType
	FromAddress  crypto.Address
	DKGID        int64
	DKGIteration int64
	Data         string
	ToAddress    crypto.Address
	Signature    []byte
}

// String returns a string representation of DKGMessage
func (m DKGMessage) String() string {
	return m.StringIndented("")
}

// StringIndented returns a string representation of the DKGMessage
func (m DKGMessage) StringIndented(indent string) string {
	return fmt.Sprintf(`DKGMessage{
%s  %v/%v/%v/%v/%v
%s}`,
		indent, m.Type, m.FromAddress, m.DKGID, m.DKGIteration, m.ToAddress,
		indent)
}

// SignBytes serialises message for signing
func (m DKGMessage) SignBytes(chainID string) []byte {
	m.Signature = nil
	sb, err := cdc.MarshalBinaryLengthPrefixed(m)
	if err != nil {
		panic(err)
	}
	return append([]byte(chainID), sb...)
}

// ValidateBasic performs basic validation
func (m *DKGMessage) ValidateBasic() error {
	if m.Type < 0 || m.Type > DKGDryRun {
		return fmt.Errorf("invalid Type")
	}
	if len(m.FromAddress) != crypto.AddressSize {
		return fmt.Errorf("expected FromAddress size to be %d bytes, got %d bytes",
			crypto.AddressSize,
			len(m.FromAddress),
		)
	}
	if m.DKGID < 0 || m.DKGIteration < 0 {
		return fmt.Errorf("invalid DKGID/DKGIteration")
	}
	if len(m.Data) == 0 || len(m.Data) > MaxDKGDataSize {
		return fmt.Errorf("expected non-empty Data size to be less than %d bytes, got %d bytes",
			MaxDKGDataSize,
			len(m.Data),
		)
	}
	// ToAddress can be empty if it is intended for everyone
	if len(m.ToAddress) != 0 && len(m.ToAddress) != crypto.AddressSize {
		return fmt.Errorf("expected ToAddress size to be %d bytes, got %d bytes",
			crypto.AddressSize,
			len(m.ToAddress),
		)
	}
	if len(m.Signature) == 0 || len(m.Signature) > MaxSignatureSize {
		return fmt.Errorf("expected Signature size be max %d bytes, got %d bytes",
			MaxSignatureSize,
			len(m.Signature),
		)
	}
	return nil
}
