package malicious

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/types"
)

func TestMessageMutatorDKG(t *testing.T) {
	testCases := []struct {
		testName        string
		setMutator      func(*MessageMutator)
		expectedNumMsgs int
		msgUnchanged    bool
	}{
		{"No mutation", func(*MessageMutator) {}, 1, true},
		{"Withhold msgs", func(mutator *MessageMutator) {
			mutator.SetDKGMessageMutation(DKGWithhold, true)
		}, 0, false},
		{"duplicate msgs", func(mutator *MessageMutator) {
			mutator.SetDKGMessageMutation(DKGDuplicate, true)
		}, 2, true},
		{"Turn off", func(mutator *MessageMutator) {
			mutator.SetDKGMessageMutation(DKGWithhold, true)
			mutator.SetDKGMessageMutation(DKGWithhold, false)
		}, 1, true},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			_, privVal := types.RandValidator(false, 10)
			mutator := NewMessageMutator(privVal)
			tc.setMutator(mutator)

			msg := exampleDKGMessage(types.DKGDryRun)
			mutatedMsg := mutator.ChangeDKGMessage(msg)

			assert.True(t, len(mutatedMsg) == tc.expectedNumMsgs)
			if len(mutatedMsg) != 0 {
				assert.Equal(t, tc.msgUnchanged, mutatedMsg[0].String() == msg.String())
				assert.Equal(t, tc.msgUnchanged, mutatedMsg[0].Data == msg.Data)
				assert.Equal(t, tc.msgUnchanged, bytes.Equal(mutatedMsg[0].Signature, msg.Signature))
			}
		})
	}
}

func exampleDKGMessage(t types.DKGMessageType) *types.DKGMessage {
	return &types.DKGMessage{
		Type:         t,
		FromAddress:  crypto.AddressHash([]byte("from_address")),
		DKGID:        1234,
		DKGIteration: 2,
		Data:         "dkg_data",
		ToAddress:    crypto.AddressHash([]byte("to_address")),
	}
}
