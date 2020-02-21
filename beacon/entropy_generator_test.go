package beacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

func groupTestSetup(nValidators int) (sm.State, []types.PrivValidator) {
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	return state, privVals
}

func TestNewEntropyGenerator(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	// Panic with no validator set
	assert.Panics(t, func() {
		NewEntropyGenerator(nil, privVals[0], "TestChain")
	})

	// Does not panic if priv validator is invalid
	var newGen *EntropyGenerator
	assert.NotPanics(t, func() {
		newGen = NewEntropyGenerator(state.Validators, nil, "TestChain")
	})
	assert.True(t, newGen.threshold == nValidators/2+1)

	// Panic OnStart() as no aeon execution unit or previous entropy set
	assert.Panics(t, func() {
		newGen.OnStart()
	})
}

func TestEntropyGeneratorNonValidator(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	newGen := NewEntropyGenerator(state.Validators, privVals[0], "TestChain")
	newGen.SetLogger(log.TestingLogger())

	// Does not panic if can not sign
	InitialiseMcl()
	aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
	newGen.SetAeonKeys(aeonExecUnit)
	newGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 0, GroupSignature: []byte("Test Entropy")})
	assert.NotPanics(t, func() {
		newGen.OnStart()
	})

}
