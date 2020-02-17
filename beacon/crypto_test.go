package beacon

import (
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
)

func TestCryptoSign(t *testing.T) {
	InitialiseMcl()
	cabinetSize := uint64(4)

	directory := "beacon/test_keys/"
	aeonExecUnit := NewAeonExecUnit(directory + "0.txt")
	defer DeleteAeonExecUnit(aeonExecUnit)

	assert.True(t, aeonExecUnit.CanSign())
	message := "HelloWorld"
	signature := aeonExecUnit.Sign(message)
	assert.True(t, aeonExecUnit.Verify(message, signature, uint64(0)))

	// Collect signatures in map
	signatureShares := NewIntStringMap()
	defer DeleteIntStringMap(signatureShares)
	signatureShares.Set(0, signature)

	// Create aeon keys for each cabinet member and entropy generators
	for i := uint64(1); i < cabinetSize; i++ {
		aeonExecUnitTemp := NewAeonExecUnit(directory + strconv.Itoa(int(i)) + ".txt")
		defer DeleteAeonExecUnit(aeonExecUnitTemp)

		assert.True(t, aeonExecUnitTemp.CanSign())
		signatureTemp := aeonExecUnitTemp.Sign(message)
		assert.True(t, aeonExecUnitTemp.Verify(message, signatureTemp, i))

		signatureShares.Set(int(i), signatureTemp)
	}
	groupSignature := aeonExecUnit.ComputeGroupSignature(signatureShares)
	assert.True(t, aeonExecUnit.VerifyGroupSignature(message, groupSignature))
}
