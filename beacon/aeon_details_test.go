package beacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/types"
)

func TestAeonDetailsNew(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)
	aeonNonSigning := NewAeonExecUnit("test_keys/non_validator.txt")
	assert.False(t, aeonNonSigning.CanSign())
	aeonSigning := NewAeonExecUnit("test_keys/0.txt")
	assert.True(t, aeonSigning.CanSign())

	// Panic with no validator set
	assert.Panics(t, func() {
		newAeonDetails(nil, privVals[0], aeonSigning, 1, 10)
	})

	// Panic with no aeon execution unit
	assert.Panics(t, func() {
		newAeonDetails(state.Validators, privVals[0], nil, 1, 10)
	})

	// Panic if can sign and no priv validator
	assert.Panics(t, func() {
		newAeonDetails(state.Validators, nil, aeonSigning, 1, 10)
	})

	// Panic if can sign and not in validators
	_, privVal := types.RandValidator(false, 30)
	assert.Panics(t, func() {
		newAeonDetails(state.Validators, privVal, aeonSigning, 1, 10)
	})

	// Panic if validator index does not match dkg index
	for _, val := range privVals {
		index, _ := state.Validators.GetByAddress(val.GetPubKey().Address())
		if index != 0 {
			assert.Panics(t, func() {
				newAeonDetails(state.Validators, val, aeonSigning, 1, 10)
			})
			break
		}
	}

	// Does not panic if priv validator is invalid if can not sign
	var newAeon *aeonDetails
	assert.NotPanics(t, func() {
		newAeon = newAeonDetails(state.Validators, nil, aeonNonSigning, 1, 10)
	})
	assert.True(t, newAeon.threshold == nValidators/2+1)

	// Does not panic for all valid inputs
	for _, val := range privVals {
		index, _ := state.Validators.GetByAddress(val.GetPubKey().Address())
		if index == 0 {
			assert.NotPanics(t, func() {
				newAeonDetails(state.Validators, val, aeonSigning, 1, 10)
			})
			break
		}
	}
}

func TestAeonDetailsSaveLoad(t *testing.T) {
	config := cfg.ResetTestRoot("aeon_details_test")

	nValidators := 4
	state, privVals := groupTestSetup(nValidators)
	aeonKeys := NewAeonExecUnit("test_keys/0.txt")
	newAeon := newAeonDetails(state.Validators, privVals[0], aeonKeys, 1, 10)

	newAeon.save(config.EntropyKeyFile())

	err, duplicateAeon := LoadAeonDetails(config.EntropyKeyFile(), state.Validators, privVals[0])
	assert.Equal(t, nil, err)
	assert.Equal(t, newAeon.Start, duplicateAeon.Start)
	assert.Equal(t, newAeon.End, duplicateAeon.End)
	assert.Equal(t, newAeon.aeonExecUnit.GroupPublicKey(), duplicateAeon.aeonExecUnit.GroupPublicKey())
	assert.Equal(t, newAeon.aeonExecUnit.PrivateKey(), duplicateAeon.aeonExecUnit.PrivateKey())
	assert.Equal(t, newAeon.aeonExecUnit.Generator(), duplicateAeon.aeonExecUnit.Generator())
	for i := 0; i < nValidators; i++ {
		assert.True(t, newAeon.aeonExecUnit.PublicKeyShares().Get(i) == duplicateAeon.aeonExecUnit.PublicKeyShares().Get(i))
		assert.True(t, newAeon.aeonExecUnit.Qual().Get(i) == duplicateAeon.aeonExecUnit.Qual().Get(i))
	}
}
