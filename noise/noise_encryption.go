package noise

import (
	"fmt"
	"io/ioutil"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
	cfg "github.com/tendermint/tendermint/config"
	cmn "github.com/tendermint/tendermint/libs/common"
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

// EncryptMsg encrypts message with noise one-way handshake with known peer public key
func EncryptMsg(staticKeyPair noise.DHKey, peerStaticPublic []byte, payload string) (string, error) {
	handshake := newHandshake(staticKeyPair, peerStaticPublic, true)
	handshakeMsg, _, _, err := handshake.WriteMessage(make([]byte, 0), []byte(payload))
	if err != nil {
		return "", err
	}
	return string(handshakeMsg), nil
}

// DecryptMsg decrypts message encrypted with noise one-way handshake with known peer public key
func DecryptMsg(staticKeyPair noise.DHKey, peerStaticPublic []byte, msg string) (string, error) {
	handshake := newHandshake(staticKeyPair, peerStaticPublic, false)
	payload, _, _, err := handshake.ReadMessage(make([]byte, 0), []byte(msg))
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// NewEncryptionKey creates a new key pair compatible with one-way handshake configuration
func NewEncryptionKey() noise.DHKey {
	encryptionKey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		panic(fmt.Sprintf("Could not generator encryption keys, err %v", err.Error()))
	}
	return encryptionKey
}

// LoadOrGenNoiseKeys either loads keys from file, or creates a new set of keys and saves them
// to file
func LoadOrGenNoiseKeys(config *cfg.Config) (noise.DHKey, error) {
	noiseKeys := noise.DHKey{}
	if cmn.FileExists(config.NoiseKeyFile()) {
		jsonBytes, err := ioutil.ReadFile(config.NoiseKeyFile())
		if err != nil {
			return noiseKeys, errors.Wrap(err, "error reading noise key file")
		}
		err = cdc.UnmarshalJSON(jsonBytes, &noiseKeys)
		if err != nil {
			return noiseKeys, errors.Wrap(err, "error unmarshalling noise keys")
		}
	} else {
		noiseKeys = NewEncryptionKey()
		keyBytes, err := cdc.MarshalJSONIndent(noiseKeys, "", "  ")
		if err != nil {
			return noiseKeys, errors.Wrap(err, "error marshalling noise key pair")
		}
		err = cmn.WriteFileAtomic(config.NoiseKeyFile(), keyBytes, 0600)
		if err != nil {
			return noiseKeys, errors.Wrap(err, "error writing noise key pair")
		}
	}
	return noiseKeys, nil
}
