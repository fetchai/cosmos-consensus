package mcl_cpp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tendermint/tendermint/libs/bits"
)

func TestMain(t *testing.M) {
	InitialiseMcl()
}

func TestSign(t *testing.T) {
	privKeyString := GenPrivKey()

	generator := "Test Generator"
	pubKey := PubKeyFromPrivate(privKeyString, generator)

	message := "Test Message"
	sign := Sign(message, privKeyString)
	assert.True(t, PairingVerify(message, sign, pubKey, generator))
}

// Verify proof of posession generated is valid
func TestProofOfPossession(t *testing.T) {
	privKeyString := GenPrivKey()

	generator := "Test Generator"
	pubKeyWithPoP := NewStringPair()
	defer DeleteStringPair(pubKeyWithPoP)
	pubKeyWithPoP = PubKeyFromPrivateWithPoP(privKeyString, generator)

	assert.True(t, PairingVerify(pubKeyWithPoP.GetFirst(), pubKeyWithPoP.GetSecond(), pubKeyWithPoP.GetFirst(),
		generator))
}

func TestCombinedSignatures(t *testing.T) {
	nVals := 10
	signerRecord := bits.NewBitArray(nVals)
	generator := "Test Generator"

	privKeyStrs := make([]string, nVals)
	publicKeyStrs := make([]string, nVals)
	for i := 0; i < nVals; i++ {
		privKeyStrs[i] = GenPrivKey()
		publicKeyStrs[i] = PubKeyFromPrivate(privKeyStrs[i], generator)
	}

	message := "Test Message"
	signatureStrs := make(map[int]string, 0)
	for i := 0; i < nVals; i++ {
		if i%2 == 0 {
			signerRecord.SetIndex(i, true)
			signatureStrs[i] = Sign(message, privKeyStrs[i])
			assert.True(t, PairingVerify(message, signatureStrs[i], publicKeyStrs[i], generator))
		}
	}

	combinedSig := NewCombinedSignature()
	combinedPubKey := NewCombinedPublicKey()
	for i := 0; i < nVals; i++ {
		if signerRecord.GetIndex(i) {
			combinedSig.Add(signatureStrs[i])
			combinedPubKey.Add(publicKeyStrs[i])
		}
	}

	assert.True(t, PairingVerify(message, combinedSig.Finish(), combinedPubKey.Finish(), generator))
}
