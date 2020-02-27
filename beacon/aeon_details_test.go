package beacon

/*
func TestNewAeonDetails(t *testing.T) {
	InitialiseMcl()
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)
	aeonNonSigning := NewAeonExecUnit("test_keys/non_validator.txt")
	aeonSigning := NewAeonExecUnit("test_keys/0.txt")

	// Panic with no validator set
	assert.Panics(t, func() {
		NewAeonDetails(nil, privVals[0], aeonExecUnit)
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

	// Does not panic if priv validator is invalid if can not sign
	var newAeon *aeonDetails
	assert.NotPanics(t, func() {
		newAeon = NewAeonDetails(state.Validators, nil, aeonNonSigning)
	})
	assert.True(t, newAeon.threshold == nValidators/2+1)
}
*/
