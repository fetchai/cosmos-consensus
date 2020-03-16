package beacon

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

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

	// Panic Start() as no aeon execution unit or previous entropy set
	assert.Panics(t, func() {
		newGen.Start()
	})
}

func TestEntropyGeneratorNonValidator(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	newGen := testEntropyGen(state.Validators, nil, -1)

	// Does not panic if can not sign
	assert.NotPanics(t, func() {
		newGen.Start()
	})

	assert.True(t, newGen.entropyComputed[1] == nil)

	// Give it entropy shares
	for i := 0; i < 3; i++ {
		privVal := privVals[i]
		index, _ := state.Validators.GetByAddress(privVal.GetPubKey().Address())
		tempGen := testEntropyGen(state.Validators, privVal, index)
		tempGen.sign(0)

		share := tempGen.entropyShares[1][index]
		newGen.applyEntropyShare(&share)
	}

	assert.Eventually(t, func() bool { return newGen.entropyComputed[1] != nil }, time.Second, 10*time.Millisecond)
}

func TestEntropyGeneratorSign(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
	newGen := testEntropyGen(state.Validators, privVals[0], index)
	newGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 2, GroupSignature: []byte("Test Entropy")})

	assert.True(t, len(newGen.entropyShares) == 0)
	t.Run("sign invalid height", func(t *testing.T) {
		newGen.sign(-1)
		assert.True(t, len(newGen.entropyShares) == 0)
	})
	t.Run("sign height too far ahead", func(t *testing.T) {
		newGen.sign(3)
		assert.True(t, len(newGen.entropyShares) == 0)
	})
	t.Run("sign valid", func(t *testing.T) {
		newGen.sign(2)
		assert.True(t, len(newGen.entropyShares[3]) == 1)
	})
	t.Run("sign valid repeated", func(t *testing.T) {
		newGen.sign(2)
		assert.True(t, len(newGen.entropyShares[3]) == 1)
	})
	t.Run("sign validator and dkg key index mismatch", func(t *testing.T) {
		indexWrong := (index + 1) % nValidators
		newGen = testEntropyGen(state.Validators, privVals[0], indexWrong)
		newGen.sign(0)
		assert.True(t, len(newGen.entropyShares[1]) == 0)
	})

	t.Run("nil priv validator with valid DKG keys", func(t *testing.T) {
		newGen = testEntropyGen(state.Validators, nil, index)
		assert.Panics(t, func() {
			newGen.sign(0)
		})
	})

	t.Run("not in validator set with DKG keys", func(t *testing.T) {
		_, randVal := types.RandValidator(false, 30)
		newGen = testEntropyGen(state.Validators, randVal, index)
		assert.Panics(t, func() {
			newGen.sign(0)
		})
	})
}

func TestEntropyGeneratorApplyShare(t *testing.T) {
	nValidators := 3
	state, privVals := groupTestSetup(nValidators)

	// Set up non-validator
	newGen := testEntropyGen(state.Validators, nil, -1)
	newGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})

	t.Run("applyShare non-validator", func(t *testing.T) {
		_, privVal := types.RandValidator(false, 30)
		aeonExecUnitInvalid := NewAeonExecUnit("test_keys/" + strconv.Itoa(int(3)) + ".txt")
		message := string(tmhash.Sum(newGen.entropyComputed[1]))
		signature := aeonExecUnitInvalid.Sign(message)
		share := types.EntropyShare{
			Height:         2,
			SignerAddress:  privVal.GetPubKey().Address(),
			SignatureShare: signature,
		}
		// Sign message
		privVal.SignEntropy(newGen.chainID, &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare old height", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})

		otherGen.sign(0)
		share := otherGen.entropyShares[1][index]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[1]) == 0)
	})
	t.Run("applyShare height far ahead", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 3, GroupSignature: []byte("Test Entropy")})

		otherGen.sign(3)
		share := otherGen.entropyShares[4][index]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[4]) == 0)
	})
	t.Run("applyShare invalid share", func(t *testing.T) {
		privVal := privVals[0]
		index, _ := state.Validators.GetByAddress(privVal.GetPubKey().Address())
		aeonExecUnitInvalid := NewAeonExecUnit("test_keys/" + strconv.Itoa(int((index+1)%3)) + ".txt")
		message := string(tmhash.Sum(newGen.entropyComputed[1]))
		signature := aeonExecUnitInvalid.Sign(message)
		share := types.EntropyShare{
			Height:         2,
			SignerAddress:  privVal.GetPubKey().Address(),
			SignatureShare: signature,
		}
		// Sign message
		privVal.SignEntropy(newGen.chainID, &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare invalid validator signature", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})

		otherGen.sign(1)
		share := otherGen.entropyShares[2][index]
		// Alter signature message
		privVals[0].SignEntropy("wrong chain ID", &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare correct", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})

		otherGen.sign(1)
		share := otherGen.entropyShares[2][index]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 1)
	})
}

func TestEntropyGeneratorApplyComputedEntropy(t *testing.T) {
	nValidators := 3
	state, privVals := groupTestSetup(nValidators)

	// Set up non-validator
	newGen := testEntropyGen(state.Validators, nil, -1)
	newGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})
	newGen.Start()

	t.Run("applyEntropy old height", func(t *testing.T) {
		entropy := types.ComputedEntropy{Height: 0, GroupSignature: []byte("Fake signature")}

		newGen.applyComputedEntropy(&entropy)
		assert.True(t, len(newGen.entropyComputed[2]) == 0)
		assert.True(t, newGen.getLastComputedEntropyHeight() == 1)
	})
	t.Run("applyEntropy height far ahead", func(t *testing.T) {
		entropy := types.ComputedEntropy{Height: 3, GroupSignature: []byte("Fake signature")}

		newGen.applyComputedEntropy(&entropy)
		assert.True(t, len(newGen.entropyComputed[3]) == 0)
		assert.True(t, newGen.getLastComputedEntropyHeight() == 1)
	})
	t.Run("applyEntropy invalid entropy", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})

		otherGen.sign(1)
		share := otherGen.entropyShares[2][index]
		entropyWrong := types.ComputedEntropy{Height: 2, GroupSignature: []byte(share.SignatureShare)}

		newGen.applyComputedEntropy(&entropyWrong)
		assert.True(t, len(newGen.entropyComputed[3]) == 0)
		assert.True(t, newGen.getLastComputedEntropyHeight() == 1)
	})
	t.Run("applyEntropy correct", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})
		otherGen.Start()

		for _, val := range privVals {
			tempIndex, _ := state.Validators.GetByAddress(val.GetPubKey().Address())
			tempGen := testEntropyGen(state.Validators, val, tempIndex)
			tempGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 1, GroupSignature: []byte("Test Entropy")})

			tempGen.sign(1)
			share := tempGen.entropyShares[2][tempIndex]
			otherGen.applyEntropyShare(&share)
		}

		assert.Eventually(t, func() bool { return otherGen.entropyComputed[2] != nil }, time.Second, 10*time.Millisecond)

		entropyRight := types.ComputedEntropy{Height: 2, GroupSignature: otherGen.entropyComputed[2]}

		newGen.applyComputedEntropy(&entropyRight)
		assert.True(t, len(newGen.entropyComputed[2]) != 0)
		assert.Eventually(t, func() bool { return newGen.getLastComputedEntropyHeight() >= 2 }, 2*computeEntropySleepDuration, 25*time.Millisecond)
	})
}

func groupTestSetup(nValidators int) (sm.State, []types.PrivValidator) {
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	return state, privVals
}

func testEntropyGen(validators *types.ValidatorSet, privVal types.PrivValidator, index int) *EntropyGenerator {
	newGen := NewEntropyGenerator(validators, privVal, "TestChain")
	newGen.SetLogger(log.TestingLogger())

	aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
	if index >= 0 {
		aeonExecUnit = NewAeonExecUnit("test_keys/" + strconv.Itoa(int(index)) + ".txt")
	}
	newGen.SetAeonKeys(aeonExecUnit)
	newGen.SetLastComputedEntropy(types.ComputedEntropy{Height: 0, GroupSignature: []byte("Test Entropy")})
	return newGen
}
