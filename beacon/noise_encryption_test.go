package beacon

import (
	"fmt"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
)

func TestNoiseNewHandshake(t *testing.T) {
	testCases := []struct {
		testName      string
		peerStaticKey []byte
		initiator     bool
	}{
		{"Initiate with correct peer key", testEncryptionKey().Public, true},
		{"Responder with correct peer key", testEncryptionKey().Public, false},
		{"Empty peer key", []byte{}, true},
		{"Invalid peer key", []byte("random garbage"), true},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			staticKey := testEncryptionKey()
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
			peerKey = testEncryptionKey()
		}, func(string) {}, false},
		{"Incorrect msg", func(noise.DHKey) {}, func(msg string) {
			msg = "mutated msg"
		}, false},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			staticKey := testEncryptionKey()
			peerStaticKey := testEncryptionKey()

			message := "Hello"
			encryptedMsg, err := encryptMsg(staticKey, peerStaticKey.Public, message)
			assert.True(t, err == nil)
			tc.mutateEncryptedMsg(encryptedMsg)
			decryptedMsg, err := decryptMsg(peerStaticKey, staticKey.Public, encryptedMsg)
			assert.Equal(t, tc.err, err != nil)
			assert.Equal(t, tc.err, decryptedMsg != message)
		})
	}
}

func testEncryptionKey() noise.DHKey {
	encryptionKey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		panic(fmt.Sprintf("Could not generator encryption keys, err %v", err.Error()))
	}
	return encryptionKey
}
