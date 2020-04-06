package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
)

func exampleDKGMessage(t DKGMessageType) *DKGMessage {
	return &DKGMessage{
		Type:         t,
		FromAddress:  crypto.AddressHash([]byte("from_address")),
		DKGID:        1234,
		DKGIteration: 2,
		Data:         []byte("dkg_data"),
		ToAddress:    crypto.AddressHash([]byte("to_address")),
	}
}

func TestDKGSignable(t *testing.T) {
	msg := exampleDKGMessage(1)
	signBytes := msg.SignBytes("test_chain_id")

	expected, err := cdc.MarshalBinaryLengthPrefixed(msg)
	require.NoError(t, err)

	require.Equal(t, append([]byte("test_chain_id"), expected...), signBytes, "Got unexpected sign bytes for Vote.")
}

func TestDKGVerifySignature(t *testing.T) {
	privVal := NewMockPV()
	pubkey := privVal.GetPubKey()

	msg := exampleDKGMessage(DKGShare)
	signBytes := msg.SignBytes("test_chain_id")

	// sign it
	err := privVal.SignDKGMessage("test_chain_id", msg)
	require.NoError(t, err)

	// verify the same vote
	valid := pubkey.VerifyBytes(msg.SignBytes("test_chain_id"), msg.Signature)
	require.True(t, valid)

	// serialize, deserialize and verify again....
	dkgMessage := new(DKGMessage)
	bs, err := cdc.MarshalBinaryLengthPrefixed(msg)
	require.NoError(t, err)
	err = cdc.UnmarshalBinaryLengthPrefixed(bs, &dkgMessage)
	require.NoError(t, err)

	// verify the transmitted vote
	newSignBytes := dkgMessage.SignBytes("test_chain_id")
	require.Equal(t, string(signBytes), string(newSignBytes))
	valid = pubkey.VerifyBytes(newSignBytes, dkgMessage.Signature)
	require.True(t, valid)
}

func TestDKGValidateBasic(t *testing.T) {
	privVal := NewMockPV()

	testCases := []struct {
		testName        string
		malleateMessage func(*DKGMessage)
		expectErr       bool
	}{
		{"Good DKGMessage", func(msg *DKGMessage) {}, false},
		{"Invalid Type", func(msg *DKGMessage) { msg.Type = DKGMessageType(-1) }, true},
		{"Invalid Type 2", func(msg *DKGMessage) { msg.Type = DKGMessageType(7) }, true},
		{"Negative DKGID", func(msg *DKGMessage) { msg.DKGID = -1 }, true},
		{"Negative DKGIteration", func(msg *DKGMessage) { msg.DKGIteration = -1 }, true},
		{"Invalid FromAddress", func(msg *DKGMessage) { msg.FromAddress = make([]byte, 1) }, true},
		{"Invalid ToAddress", func(msg *DKGMessage) { msg.FromAddress = make([]byte, 1) }, true},
		{"Empty ToAddress", func(msg *DKGMessage) { msg.ToAddress = make([]byte, 0) }, false},
		{"Invalid Data", func(msg *DKGMessage) { msg.Data = make([]byte, 0) }, true},
		{"Too big Data", func(msg *DKGMessage) { msg.Data = make([]byte, MaxDKGDataSize+1) }, true},
		{"Invalid Signature", func(msg *DKGMessage) { msg.Signature = nil }, true},
		{"Too big Signature", func(msg *DKGMessage) { msg.Signature = make([]byte, MaxSignatureSize+1) }, true},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			msg := exampleDKGMessage(DKGShare)
			err := privVal.SignDKGMessage("test_chain_id", msg)
			require.NoError(t, err)
			tc.malleateMessage(msg)
			err = msg.ValidateBasic()
			assert.Equal(t, tc.expectErr, err != nil, "Validate Basic had an unexpected result %v", err)
		})
	}
}
