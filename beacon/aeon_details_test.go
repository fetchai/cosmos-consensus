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
	aeonNonSigning := testAeonFromFile("test_keys/non_validator.txt")
	assert.False(t, aeonNonSigning.CanSign())
	aeonSigning := testAeonFromFile("test_keys/validator_0_of_4.txt")
	assert.True(t, aeonSigning.CanSign())

	// Error if no validator set
	_, err := newAeonDetails(privVals[0], 1, 1, nil, aeonSigning, 1, 10)
	assert.NotNil(t, err)

	// Error if no aeon execution unit
	_, err = newAeonDetails(privVals[0], 1, 1, state.Validators, nil, 1, 10)
	assert.NotNil(t, err)

	// Error if can sign and no priv validator
	_, err = newAeonDetails(nil, 1, 1, state.Validators, aeonSigning, 1, 10)
	assert.NotNil(t, err)

	// Error if can sign and not in validators
	_, privVal := types.RandValidator(false, 30)
	_, err = newAeonDetails(privVal, 1, 1, state.Validators, aeonSigning, 1, 10)
	assert.NotNil(t, err)

	// Error if validator index does not match dkg index
	for _, val := range privVals {
		pubKey, _ := val.GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		if index != 0 {
			_, err = newAeonDetails(val, 1, 1, state.Validators, aeonSigning, 1, 10)
			assert.NotNil(t, err)
			break
		}
	}

	// No error if priv validator is invalid if can not sign
	newAeon, err := newAeonDetails(nil, 1, 1, state.Validators, aeonNonSigning, 1, 10)
	assert.Nil(t, err)
	assert.True(t, newAeon.threshold == nValidators/2+1)

	// No error for all valid inputs
	for _, val := range privVals {
		pubKey, _ := val.GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		if index == 0 {
			_, err = newAeonDetails(val, 1, 1, state.Validators, aeonSigning, 1, 10)
			assert.Nil(t, err)
			break
		}
	}
}

func TestAeonDetailsSaveLoad(t *testing.T) {
	config := cfg.ResetTestRoot("aeon_details_test")

	nValidators := 4
	state, privVals := groupTestSetup(nValidators)
	aeonKeys := testAeonFromFile("test_keys/validator_0_of_4.txt")
	newAeon, _ := newAeonDetails(privVals[0], 1, 1, state.Validators, aeonKeys, 1, 10)

	saveAeons(config.EntropyKeyFile(), newAeon)

	aeonDetailsFiles, err := loadAeonDetailsFiles(config.EntropyKeyFile())
	assert.Equal(t, nil, err)
	duplicateAeon, err := loadAeonDetails(aeonDetailsFiles[0], state.Validators, privVals[0])
	assert.Nil(t, err)
	assert.Equal(t, newAeon.validatorHeight, duplicateAeon.validatorHeight)
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

func TestAeonDetailsNoKeys(t *testing.T) {
	config := cfg.ResetTestRoot("keyless_aeon_details_test")

	newAeon := keylessAeonDetails(1, 1, 1, 10)
	assert.True(t, newAeon.aeonExecUnit == nil)
	saveAeons(config.EntropyKeyFile(), newAeon)

	keyFiles, err := loadAeonDetailsFiles(config.BaseConfig.EntropyKeyFile())
	assert.Equal(t, nil, err)
	assert.NotPanics(t, func() {
		loadAeonDetails(keyFiles[0], nil, nil)
	})
}
