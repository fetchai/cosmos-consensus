package beacon

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	bits "github.com/tendermint/tendermint/libs/bits"
	"github.com/tendermint/tendermint/mcl_cpp"
	"github.com/tendermint/tendermint/types"
)

func TestCryptoSign(t *testing.T) {
	cabinetSize := uint(4)

	directory := "test_keys/"
	aeonExecUnit := testAeonFromFile(directory + "validator_0_of_4.txt")

	assert.True(t, aeonExecUnit.CanSign())
	message := "HelloWorld"
	signature := aeonExecUnit.Sign(message, 0)
	assert.True(t, aeonExecUnit.Verify(message, signature, uint(0)))

	// Collect signatures in map
	signatureShares := mcl_cpp.NewIntStringMap()
	defer mcl_cpp.DeleteIntStringMap(signatureShares)
	signatureShares.Set(0, signature)

	// Create aeon keys for each cabinet member and entropy generators
	for i := uint(1); i < cabinetSize; i++ {
		aeonExecUnitTemp := testAeonFromFile(directory + "validator_" + strconv.Itoa(int(i)) + "_of_4.txt")

		assert.True(t, aeonExecUnitTemp.CanSign())
		signatureTemp := aeonExecUnitTemp.Sign(message, i)
		assert.True(t, len([]byte(signatureTemp)) <= types.MaxEntropyShareSize)
		assert.True(t, aeonExecUnitTemp.Verify(message, signatureTemp, i))

		signatureShares.Set(i, signatureTemp)
	}
	groupSignature := aeonExecUnit.ComputeGroupSignature(signatureShares)
	assert.True(t, len([]byte(groupSignature)) <= types.MaxThresholdSignatureSize)
	assert.True(t, aeonExecUnit.VerifyGroupSignature(message, groupSignature))
}

func TestCryptoNonValidator(t *testing.T) {
	aeonExecUnit := testAeonFromFile("test_keys/non_validator.txt")

	assert.False(t, aeonExecUnit.CanSign())
}

func TestHonestDkg(t *testing.T) {
	cabinetSize := uint(3)
	threshold := uint(2)

	// Set up two honest beacon managers
	beaconManagers := make([]mcl_cpp.BeaconSetupService, cabinetSize)
	for index := uint(0); index < cabinetSize; index++ {
		beaconManagers[index] = mcl_cpp.NewBeaconSetupService(cabinetSize, threshold, index)
	}

	// Distribute shares
	for index := uint(0); index < cabinetSize; index++ {
		coefficients := beaconManagers[index].GetCoefficients()
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index != index1 {
				beaconManagers[index1].OnShares(beaconManagers[index].GetShare(index1), index)
				beaconManagers[index1].OnCoefficients(coefficients, index)
			}
		}
	}

	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllCoefficientsAndShares())
	}

	// Distribute complaints
	for index := uint(0); index < cabinetSize; index++ {
		complaints := beaconManagers[index].GetComplaints()
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index != index1 {
				beaconManagers[index1].OnComplaints(complaints, index)
			}
		}
	}

	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllComplaints())
	}

	// Distribute complaints answers
	for index := uint(0); index < cabinetSize; index++ {
		complaintAnswer := beaconManagers[index].GetComplaintAnswers()
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			beaconManagers[index1].OnComplaintAnswers(complaintAnswer, index)
		}
	}

	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllComplaintAnswers())
		assert.True(t, beaconManagers[index].BuildQual() == cabinetSize)
	}

	// Distribute qual coefficients
	for index := uint(0); index < cabinetSize; index++ {
		coefficients := beaconManagers[index].GetQualCoefficients()
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index != index1 {
				beaconManagers[index1].OnQualCoefficients(coefficients, index)
			}
		}
	}

	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllQualCoefficients())
	}

	// Distribute qual complaints
	for index := uint(0); index < cabinetSize; index++ {
		complaints := beaconManagers[index].GetQualComplaints()
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index != index1 {
				beaconManagers[index1].OnQualComplaints(complaints, index)
			}
		}
	}

	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllQualComplaints())
		assert.True(t, beaconManagers[index].CheckQualComplaints())
	}

	// Distribute reconstruction shares
	for index := uint(0); index < cabinetSize; index++ {
		complaints := beaconManagers[index].GetReconstructionShares()
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index != index1 {
				beaconManagers[index1].OnReconstructionShares(complaints, index)
			}
		}
	}

	outputs := make([]mcl_cpp.BaseAeon, cabinetSize)
	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllReconstructionShares())
		assert.True(t, beaconManagers[index].RunReconstruction())
		outputs[index] = beaconManagers[index].ComputePublicKeys()
	}

	// Check all group public keys agree with threshold signing
	message := "TestMessage"
	sigShares := mcl_cpp.NewIntStringMap()
	defer mcl_cpp.DeleteIntStringMap(sigShares)
	for index := uint(0); index < cabinetSize; index++ {
		signature := outputs[index].Sign(message, index)
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index != index1 {
				assert.True(t, outputs[index1].Verify(message, signature, index))
			}
		}
		sigShares.Set(index, signature)
	}
	groupSig := outputs[0].ComputeGroupSignature(sigShares)
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, outputs[index].VerifyGroupSignature(message, groupSig))
	}

}

func TestSign(t *testing.T) {
	privKeyString := mcl_cpp.GenPrivKey()

	pubKey := mcl_cpp.PubKeyFromPrivate(privKeyString)
	assert.True(t, len(pubKey) != 0)

	message := "Test Message"
	sign := mcl_cpp.Sign(message, privKeyString)
	assert.True(t, len(sign) != 0)
	assert.True(t, mcl_cpp.PairingVerify(message, sign, pubKey))
}

// Verify proof of posession generated is valid
func TestProofOfPossession(t *testing.T) {
	privKeyString := mcl_cpp.GenPrivKey()

	pubKeyWithPoP := mcl_cpp.NewStringPair()
	defer mcl_cpp.DeleteStringPair(pubKeyWithPoP)
	pubKeyWithPoP = mcl_cpp.PubKeyFromPrivateWithPoP(privKeyString)

	assert.True(t, mcl_cpp.PairingVerify(pubKeyWithPoP.GetFirst(), pubKeyWithPoP.GetSecond(), pubKeyWithPoP.GetFirst()))
}

func TestCombinedSignatures(t *testing.T) {
	nVals := 10
	signerRecord := bits.NewBitArray(nVals)

	privKeyStrs := make([]string, nVals)
	publicKeyStrs := make([]string, nVals)
	for i := 0; i < nVals; i++ {
		privKeyStrs[i] = mcl_cpp.GenPrivKey()
		publicKeyStrs[i] = mcl_cpp.PubKeyFromPrivate(privKeyStrs[i])
	}

	message := "Test Message"
	signatureStrs := make(map[int]string, 0)
	for i := 0; i < nVals; i++ {
		if i == 0 {
			signerRecord.SetIndex(i, true)
			signatureStrs[i] = mcl_cpp.Sign(message, privKeyStrs[i])
			assert.True(t, len(signatureStrs[i]) != 0)
			assert.True(t, mcl_cpp.PairingVerify(message, signatureStrs[i], publicKeyStrs[i]))
		}
	}

	sigs := mcl_cpp.NewStringVector()
	pubKeys := mcl_cpp.NewStringVector()
	for i := 0; i < nVals; i++ {
		if signerRecord.GetIndex(i) {
			sigs.Add(signatureStrs[i])
			pubKeys.Add(publicKeyStrs[i])
		}
	}

	assert.True(t, mcl_cpp.PairingVerifyCombinedSig(message, mcl_cpp.CombineSignatures(sigs), pubKeys))
}

func testAeonFromFile(filename string) mcl_cpp.BaseAeon {
	//Aeon type here must match those in key files
	return mcl_cpp.NewBlsAeon(filename)
}

// Benchmarks the function used to compute the public key used to verify combined signatures
// This operation is costly due to the string to mcl conversions
func BenchmarkCombinedPubKey(b *testing.B) {
	nVals := 100

	privKeyStrs := make([]string, nVals)
	publicKeyStrs := make([]string, nVals)
	for i := 0; i < nVals; i++ {
		privKeyStrs[i] = mcl_cpp.GenPrivKey()
		publicKeyStrs[i] = mcl_cpp.PubKeyFromPrivate(privKeyStrs[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pubKeys := mcl_cpp.NewStringVector()
		defer mcl_cpp.DeleteStringVector(pubKeys)
		for i := 0; i < nVals; i++ {
			pubKeys.Add(publicKeyStrs[i])
		}
		assert.True(b, len(mcl_cpp.CombinePublicKeys(pubKeys)) != 0)
	}
}

// Benchmarks the combined signature verification function used by validators to verify blocks
func BenchmarkVerifyCombinedSignature(b *testing.B) {
	nVals := 100
	signerRecord := bits.NewBitArray(nVals)

	privKeyStrs := make([]string, nVals)
	publicKeyStrs := make([]string, nVals)
	for i := 0; i < nVals; i++ {
		privKeyStrs[i] = mcl_cpp.GenPrivKey()
		publicKeyStrs[i] = mcl_cpp.PubKeyFromPrivate(privKeyStrs[i])
	}

	message := "Test Message"
	signatureStrs := make(map[int]string, 0)
	for i := 0; i < nVals; i++ {
		signerRecord.SetIndex(i, true)
		signatureStrs[i] = mcl_cpp.Sign(message, privKeyStrs[i])
	}

	sigs := mcl_cpp.NewStringVector()
	pubKeys := mcl_cpp.NewStringVector()
	defer mcl_cpp.DeleteStringVector(sigs)
	defer mcl_cpp.DeleteStringVector(pubKeys)
	for i := 0; i < nVals; i++ {
		if signerRecord.GetIndex(i) {
			sigs.Add(signatureStrs[i])
			pubKeys.Add(publicKeyStrs[i])
		}
	}
	combined_sig := mcl_cpp.CombineSignatures(sigs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mcl_cpp.PairingVerifyCombinedSig(message, combined_sig, pubKeys)
	}
}
