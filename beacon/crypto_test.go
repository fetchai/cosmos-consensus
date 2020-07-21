package beacon

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
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
	signatureShares := NewIntStringMap()
	defer DeleteIntStringMap(signatureShares)
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
	beaconManagers := make([]BeaconSetupService, cabinetSize)
	for index := uint(0); index < cabinetSize; index++ {
		beaconManagers[index] = NewBeaconSetupService(cabinetSize, threshold, index)
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
			if index != index1 {
				beaconManagers[index1].OnComplaintAnswers(complaintAnswer, index)
			}
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

	outputs := make([]BaseAeon, cabinetSize)
	// Check every one has received all required coefficients and shares
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].ReceivedAllReconstructionShares())
		assert.True(t, beaconManagers[index].RunReconstruction())
		outputs[index] = beaconManagers[index].ComputePublicKeys()
	}

	// Check all group public keys agree with threshold signing
	message := "TestMessage"
	sigShares := NewIntStringMap()
	defer DeleteIntStringMap(sigShares)
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

func testAeonFromFile(filename string) BaseAeon {
	//Aeon type here must match those in key files
	return NewBlsAeon(filename)
}
