package noise

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	cfg "github.com/tendermint/tendermint/config"
)

func TestNoiseNewHandshake(t *testing.T) {
	testCases := []struct {
		testName      string
		peerStaticKey []byte
		initiator     bool
	}{
		{"Initiate with correct peer key", NewEncryptionKey().Public, true},
		{"Responder with correct peer key", NewEncryptionKey().Public, false},
		{"Empty peer key", []byte{}, true},
		{"Invalid peer key", []byte("random garbage"), true},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			staticKey := NewEncryptionKey()
			peerStaticKey := tc.peerStaticKey

			var handshake *noise.HandshakeState
			assert.NotPanics(t, func() {
				handshake = newHandshake(staticKey, peerStaticKey, tc.initiator)
			})
			assert.NotEqual(t, nil, handshake)
		})
	}
}

func TestNoiseEncryption(t *testing.T) {
	testCases := []struct {
		testName            string
		mutateDecryptionKey func(noise.DHKey)
		mutateEncryptedMsg  func(string)
		err                 bool
	}{
		{"Correct key", func(noise.DHKey) {}, func(string) {}, false},
		{"Incorrect key", func(peerKey noise.DHKey) {
			peerKey = NewEncryptionKey()
		}, func(string) {}, false},
		{"Incorrect msg", func(noise.DHKey) {}, func(msg string) {
			msg = "mutated msg"
		}, false},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			staticKey := NewEncryptionKey()
			peerStaticKey := NewEncryptionKey()

			message := "Hello"
			encryptedMsg, err := EncryptMsg(staticKey, peerStaticKey.Public, message)
			assert.True(t, err == nil)
			tc.mutateEncryptedMsg(encryptedMsg)
			decryptedMsg, err := DecryptMsg(peerStaticKey, staticKey.Public, encryptedMsg)
			assert.Equal(t, tc.err, err != nil)
			assert.Equal(t, tc.err, decryptedMsg != message)
		})
	}
}

func TestLoadOrGenerateKeys(t *testing.T) {
	config := cfg.ResetTestRoot("noise_test")

	noiseKeys, err := LoadOrGenNoiseKeys(config)
	assert.True(t, err == nil)
	assert.True(t, len(noiseKeys.Public) != 0)
	assert.True(t, len(noiseKeys.Private) != 0)

	noiseKeysFromFile, err := LoadOrGenNoiseKeys(config)
	assert.True(t, err == nil)
	assert.True(t, bytes.Equal(noiseKeys.Public, noiseKeysFromFile.Public))
	assert.True(t, bytes.Equal(noiseKeys.Private, noiseKeysFromFile.Private))
}
