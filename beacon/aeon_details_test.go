package beacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/types"
)

func TestNewAeonDetails(t *testing.T) {
	InitialiseMcl()
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)
	aeonNonSigning := NewAeonExecUnit("test_keys/non_validator.txt")
	assert.False(t, aeonNonSigning.CanSign())
	aeonSigning := NewAeonExecUnit("test_keys/0.txt")
	assert.True(t, aeonSigning.CanSign())

	// Panic with no validator set
	assert.Panics(t, func() {
		NewAeonDetails(nil, privVals[0], aeonSigning)
	})

	// Panic with no aeon execution unit
	assert.Panics(t, func() {
		NewAeonDetails(state.Validators, privVals[0], nil)
	})

	// Panic if can sign and no priv validator
	assert.Panics(t, func() {
		NewAeonDetails(state.Validators, nil, aeonSigning)
	})

	// Panic if can sign and not in validators
	_, privVal := types.RandValidator(false, 30)
	assert.Panics(t, func() {
		NewAeonDetails(state.Validators, privVal, aeonSigning)
	})

	// Panic if validator index does not match dkg index
	for _, val := range privVals {
		index, _ := state.Validators.GetByAddress(val.GetPubKey().Address())
		if index != 0 {
			assert.Panics(t, func() {
				NewAeonDetails(state.Validators, val, aeonSigning)
			})
			break
		}
	}

	// Does not panic if priv validator is invalid if can not sign
	var newAeon *aeonDetails
	assert.NotPanics(t, func() {
		newAeon = NewAeonDetails(state.Validators, nil, aeonNonSigning)
	})
	assert.True(t, newAeon.threshold == nValidators/2+1)

	// Does not panic for all valid inputs
	// Does not panic if priv validator is invalid if can not sign
	for _, val := range privVals {
		index, _ := state.Validators.GetByAddress(val.GetPubKey().Address())
		if index == 0 {
			assert.NotPanics(t, func() {
				NewAeonDetails(state.Validators, val, aeonSigning)
			})
			break
		}
	}
}
