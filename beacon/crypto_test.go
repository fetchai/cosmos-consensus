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
	aeonExecUnit := NewAeonExecUnit(directory + "0.txt")
	defer DeleteAeonExecUnit(aeonExecUnit)

	assert.True(t, aeonExecUnit.CanSign())
	message := "HelloWorld"
	signature := aeonExecUnit.Sign(message)
	assert.True(t, aeonExecUnit.Verify(message, signature, uint(0)))

	// Collect signatures in map
	signatureShares := NewIntStringMap()
	defer DeleteIntStringMap(signatureShares)
	signatureShares.Set(0, signature)

	// Create aeon keys for each cabinet member and entropy generators
	for i := uint(1); i < cabinetSize; i++ {
		aeonExecUnitTemp := NewAeonExecUnit(directory + strconv.Itoa(int(i)) + ".txt")
		defer DeleteAeonExecUnit(aeonExecUnitTemp)

		assert.True(t, aeonExecUnitTemp.CanSign())
		signatureTemp := aeonExecUnitTemp.Sign(message)
		assert.True(t, len([]byte(signatureTemp)) <= types.MaxEntropyShareSize)
		assert.True(t, aeonExecUnitTemp.Verify(message, signatureTemp, i))

		signatureShares.Set(int(i), signatureTemp)
	}
	groupSignature := aeonExecUnit.ComputeGroupSignature(signatureShares)
	assert.True(t, len([]byte(groupSignature)) <= types.MaxThresholdSignatureSize)
	assert.True(t, aeonExecUnit.VerifyGroupSignature(message, groupSignature))
}

func TestCryptoNonValidator(t *testing.T) {
	aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
	defer DeleteAeonExecUnit(aeonExecUnit)

	assert.False(t, aeonExecUnit.CanSign())
}

func TestDkg(t *testing.T) {
	cabinetSize := uint(3)
	threshold := uint(2)

	// Set up two honest beacon managers
	beaconManagers := make([]BeaconManager, cabinetSize)
	for index := uint(0); index < cabinetSize; index++ {
		beaconManagers[index] = NewBeaconManager()
	}

	// Reset all managers
	for index := uint(0); index < cabinetSize; index++ {
		beaconManagers[index].NewCabinet(cabinetSize, threshold, index)
	}

	// Check reset for one manager
	for index := uint(0); index < cabinetSize; index++ {
		assert.True(t, beaconManagers[index].Cabinet_index() == index)
		assert.True(t, beaconManagers[index].Polynomial_degree()+1 == threshold)
		assert.True(t, len(beaconManagers[index].Group_public_key()) == 0)
	}

	for _, manager := range beaconManagers {
		manager.GenerateCoefficients()
	}

	myIndex := uint(0)
	honest := uint(1)
	malicious := uint(2)

	// Add shares and coefficients passing verification from someone and check that they are entered
	// in correctly
	honestShare := beaconManagers[honest].GetOwnShares(myIndex)
	beaconManagers[myIndex].AddShares(honest, honestShare)
	beaconManagers[myIndex].AddCoefficients(honest, beaconManagers[honest].GetCoefficients())
	receivedShare := beaconManagers[myIndex].GetReceivedShares(honest)
	assert.True(t, honestShare.GetFirst() == receivedShare.GetFirst())
	assert.True(t, honestShare.GetSecond() == receivedShare.GetSecond())

	// Add shares and coefficients failing verification from malicious party
	beaconManagers[myIndex].AddShares(malicious, honestShare)
	beaconManagers[myIndex].AddCoefficients(malicious, beaconManagers[malicious].GetCoefficients())
	receivedShare2 := beaconManagers[myIndex].GetReceivedShares(malicious)
	assert.True(t, honestShare.GetFirst() == receivedShare2.GetFirst())
	assert.True(t, honestShare.GetSecond() == receivedShare2.GetSecond())

	coeffReceived := NewIntVector()
	defer DeleteIntVector(coeffReceived)
	coeffReceived.Add(honest)
	coeffReceived.Add(malicious)
	assert.True(t, coeffReceived.Size() == 2)
	complaints := NewIntVector()
	defer DeleteIntVector(complaints)
	beaconManagers[myIndex].ComputeComplaints(coeffReceived, complaints)
	assert.True(t, complaints.Size() == 1)
	assert.True(t, complaints.Get(0) == malicious)

	// Submit false complaints answer
	wrongAnswer := NewGoExposedShare()
	defer DeleteGoExposedShare(wrongAnswer)
	wrongAnswer.SetFirst(myIndex)
	wrongAnswer.SetSecond(honestShare)
	assert.False(t, beaconManagers[myIndex].VerifyComplaintAnswer(malicious, wrongAnswer))

	// Submit correct correct complaints answer and check values get replaced
	correctAnswer := NewGoExposedShare()
	defer DeleteGoExposedShare(correctAnswer)
	correctAnswer.SetFirst(myIndex)
	correctAnswer.SetSecond(beaconManagers[malicious].GetOwnShares(myIndex))
	assert.True(t, beaconManagers[myIndex].VerifyComplaintAnswer(malicious, correctAnswer))
	assert.True(t, beaconManagers[myIndex].GetReceivedShares(malicious).GetFirst() ==
		beaconManagers[malicious].GetOwnShares(myIndex).GetFirst())
	assert.True(t, beaconManagers[myIndex].GetReceivedShares(malicious).GetSecond() ==
		beaconManagers[malicious].GetOwnShares(myIndex).GetSecond())

	// Distribute correct shares and coefficients amongst everyone else
	for index := uint(1); index < cabinetSize; index++ {
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index1 != index {
				beaconManagers[index].AddShares(index1, beaconManagers[index1].GetOwnShares(index))
				beaconManagers[index].AddCoefficients(index1, beaconManagers[index1].GetCoefficients())
			}
		}
	}

	// Since bad shares have been replaced set qual to be everyone
	qual := NewIntVector()
	defer DeleteIntVector(qual)
	for index := uint(0); index < cabinetSize; index++ {
		qual.Add(index)
	}
	for index := uint(0); index < cabinetSize; index++ {
		beaconManagers[index].SetQual(qual)
		beaconManagers[index].ComputeSecretShare()
	}

	// Add honest qual coefficients
	beaconManagers[myIndex].AddQualCoefficients(honest, beaconManagers[honest].GetQualCoefficients())

	// Verify qual coefficients before malicious submitted coefficients - expect complaint against
	// them
	qualComplaintsTest := NewGoSharesExposedMap()
	defer DeleteGoSharesExposedMap(qualComplaintsTest)
	qualComplaintsTest.Set(malicious, beaconManagers[myIndex].GetReceivedShares(malicious))
	qualReceived := NewIntVector()
	defer DeleteIntVector(qualReceived)
	qualReceived.Add(honest)
	actualQualComplaints := beaconManagers[myIndex].ComputeQualComplaints(qualReceived)
	assert.True(t, actualQualComplaints.Size() == 1)
	assert.True(t, actualQualComplaints.Get(malicious).GetFirst() == qualComplaintsTest.Get(malicious).GetFirst())
	assert.True(t, actualQualComplaints.Get(malicious).GetSecond() == qualComplaintsTest.Get(malicious).GetSecond())

	// Add wrong qual coefficients
	beaconManagers[myIndex].AddQualCoefficients(malicious, beaconManagers[honest].GetQualCoefficients())

	// Verify qual coefficients and check the complaints
	actualQualComplaints1 := beaconManagers[myIndex].ComputeQualComplaints(coeffReceived)
	assert.True(t, actualQualComplaints1.Size() == 1)
	assert.True(t, actualQualComplaints1.Get(malicious).GetFirst() == qualComplaintsTest.Get(malicious).GetFirst())
	assert.True(t, actualQualComplaints1.Get(malicious).GetSecond() == qualComplaintsTest.Get(malicious).GetSecond())

	// Share qual coefficients amongst other nodes
	for index := uint(1); index < cabinetSize; index++ {
		for index1 := uint(0); index1 < cabinetSize; index1++ {
			if index1 != index {
				beaconManagers[index].AddQualCoefficients(index1, beaconManagers[index1].GetQualCoefficients())
			}
		}
	}

	// Invalid qual complaint
	incorrectComplaint := NewGoExposedShare()
	defer DeleteGoExposedShare(incorrectComplaint)
	incorrectComplaint.SetFirst(honest)
	incorrectComplaint.SetSecond(beaconManagers[honest].GetOwnShares(malicious))
	assert.True(t, malicious == beaconManagers[myIndex].VerifyQualComplaint(malicious, incorrectComplaint))
	// Qual complaint which fails first
	failCheck1 := NewGoExposedShare()
	defer DeleteGoExposedShare(failCheck1)
	failCheck1.SetFirst(malicious)
	failCheck1.SetSecond(honestShare)
	assert.True(t, honest == beaconManagers[myIndex].VerifyQualComplaint(honest, failCheck1))
	failCheck2 := NewGoExposedShare()
	defer DeleteGoExposedShare(failCheck2)
	failCheck2.SetFirst(malicious)
	failCheck2.SetSecond(beaconManagers[honest].GetReceivedShares(malicious))
	assert.True(t, malicious == beaconManagers[myIndex].VerifyQualComplaint(honest, failCheck2))

	// Verify invalid reconstruction share
	incorrectReconstructionShare := NewGoExposedShare()
	defer DeleteGoExposedShare(incorrectReconstructionShare)
	incorrectReconstructionShare.SetFirst(honest)
	incorrectReconstructionShare.SetSecond(honestShare)
	beaconManagers[myIndex].VerifyReconstructionShare(malicious, incorrectReconstructionShare)
	// Verify valid reconstruction share
	correctReconstructionShare := NewGoExposedShare()
	defer DeleteGoExposedShare(correctReconstructionShare)
	correctReconstructionShare.SetFirst(malicious)
	correctReconstructionShare.SetSecond(beaconManagers[honest].GetReceivedShares(malicious))
	beaconManagers[myIndex].VerifyReconstructionShare(honest, correctReconstructionShare)
	// Duplicate good reconstruction share
	beaconManagers[myIndex].VerifyReconstructionShare(honest, correctReconstructionShare)

	// Run reconstruction with not enough shares
	assert.False(t, beaconManagers[myIndex].RunReconstruction())
	beaconManagers[myIndex].AddReconstructionShare(malicious)
	// Run reconstruction with enough shares
	assert.True(t, beaconManagers[myIndex].RunReconstruction())
	// Skip reconstruction for oneself
	myReconstructionShare1 := NewGoExposedShare()
	defer DeleteGoExposedShare(myReconstructionShare1)
	myReconstructionShare1.SetFirst(myIndex)
	myReconstructionShare1.SetSecond(beaconManagers[myIndex].GetOwnShares(honest))
	myReconstructionShare2 := NewGoExposedShare()
	defer DeleteGoExposedShare(myReconstructionShare2)
	myReconstructionShare2.SetFirst(myIndex)
	myReconstructionShare2.SetSecond(beaconManagers[myIndex].GetOwnShares(malicious))
	beaconManagers[myIndex].VerifyReconstructionShare(honest, myReconstructionShare2)
	beaconManagers[myIndex].VerifyReconstructionShare(malicious, myReconstructionShare2)
	assert.True(t, beaconManagers[myIndex].RunReconstruction())

	for index := uint(0); index < cabinetSize; index++ {
		beaconManagers[index].ComputePublicKeys()
	}

	checkPublicKey := beaconManagers[myIndex].Group_public_key()
	for index := uint(1); index < cabinetSize; index++ {
		assert.True(t, checkPublicKey == beaconManagers[index].Group_public_key())
	}

}
