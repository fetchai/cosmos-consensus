package beacon

import (
	"fmt"

	"github.com/flynn/noise"
)

func newHandshake(staticKeyPair noise.DHKey, peerStaticPublic []byte, initiator bool) *noise.HandshakeState {
	noiseConfig := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Pattern:       noise.HandshakeK,
		Initiator:     initiator,
		StaticKeypair: staticKeyPair,
		PeerStatic:    peerStaticPublic,
	}

	handshake, err := noise.NewHandshakeState(noiseConfig)
	if err != nil {
		panic(fmt.Errorf("newHandshake, error %v", err))
	}
	return handshake
}

func encryptMsg(staticKeyPair noise.DHKey, peerStaticPublic []byte, payload string) (string, error) {
	handshake := newHandshake(staticKeyPair, peerStaticPublic, true)
	handshakeMsg, _, _, err := handshake.WriteMessage(make([]byte, 0), []byte(payload))
	if err != nil {
		return "", err
	}
	return string(handshakeMsg), nil
}

func decryptMsg(staticKeyPair noise.DHKey, peerStaticPublic []byte, msg string) (string, error) {
	handshake := newHandshake(staticKeyPair, peerStaticPublic, false)
	payload, _, _, err := handshake.ReadMessage(make([]byte, 0), []byte(msg))
	if err != nil {
		return "", err
	}
	return string(payload), nil
}
