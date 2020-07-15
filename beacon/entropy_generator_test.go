package beacon

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

func TestEntropyGeneratorStart(t *testing.T) {
	testCases := []struct {
		testName string
		setup    func(*EntropyGenerator)
	}{
		{"Genesis start up", func(*EntropyGenerator) {}},
		{"With last entropy", func(eg *EntropyGenerator) {
			eg.SetLastComputedEntropy(0, []byte("Test Entropy"))
		}},
		{"With aeon", func(eg *EntropyGenerator) {
			nValidators := 4
			state, _ := groupTestSetup(nValidators)
			aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
			aeonDetails, _ := newAeonDetails(nil, 1, state.Validators, aeonExecUnit, 1, 10)
			eg.SetNextAeonDetails(aeonDetails)
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			newGen := testEntropyGenerator()
			tc.setup(newGen)
			assert.NotPanics(t, func() {
				newGen.Start()
			})
		})
	}
}

func TestEntropyGeneratorSetAeon(t *testing.T) {
	newGen := testEntropyGenerator()
	// Set be on the end of first aeon
	lastBlockHeight := int64(99)
	newGen.setLastBlockHeight(lastBlockHeight)

	testCases := []struct {
		testName string
		start    int64
		end      int64
		aeonSet  bool
	}{
		{"Old aeon", 1, 10, false},
		{"Old aeon end", lastBlockHeight, lastBlockHeight, false},
		{"Correct aeon", lastBlockHeight + 1, lastBlockHeight + 10, true},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			state, _ := groupTestSetup(4)
			aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
			aeonDetails, _ := newAeonDetails(nil, 1, state.Validators, aeonExecUnit, tc.start, tc.end)
			newGen.SetNextAeonDetails(aeonDetails)
			newGen.changeKeys()
			assert.Equal(t, newGen.isSigningEntropy(), tc.aeonSet)
		})
	}
}

func TestEntropyGeneratorNonValidator(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	newGen := testEntropyGen(state.Validators, nil, -1)

	// Does not panic if can not sign
	assert.NotPanics(t, func() {
		newGen.Start()
	})

	assert.True(t, newGen.getLastComputedEntropyHeight() == 0)

	// Give it entropy shares
	for i := 0; i < 3; i++ {
		privVal := privVals[i]
		index, _ := state.Validators.GetByAddress(privVal.GetPubKey().Address())
		tempGen := testEntropyGen(state.Validators, privVal, index)
		tempGen.sign()

		share := tempGen.entropyShares[1][uint(index)]
		newGen.applyEntropyShare(&share)
	}

	assert.Eventually(t, func() bool { return newGen.getLastComputedEntropyHeight() == 1 }, time.Second, 10*time.Millisecond)
}

func TestEntropyGeneratorSign(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
	newGen := testEntropyGen(state.Validators, privVals[0], index)
	newGen.SetLastComputedEntropy(2, []byte("Test Entropy"))
	newGen.setLastBlockHeight(2)

	assert.True(t, len(newGen.entropyShares) == 0)
	t.Run("sign valid", func(t *testing.T) {
		newGen.sign()
		assert.True(t, len(newGen.entropyShares[3]) == 1)
	})
	t.Run("sign valid repeated", func(t *testing.T) {
		newGen.sign()
		assert.True(t, len(newGen.entropyShares[3]) == 1)
	})
}

func TestEntropyGeneratorApplyShare(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	// Set up non-validator
	newGen := testEntropyGen(state.Validators, nil, -1)
	newGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
	newGen.setLastBlockHeight(1)

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
		privVal.SignEntropy(newGen.baseConfig.ChainID(), &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare old height", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)

		otherGen.sign()
		share := otherGen.entropyShares[1][uint(index)]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[1]) == 0)
	})
	t.Run("applyShare height far ahead", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(3, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(3)

		otherGen.sign()
		share := otherGen.entropyShares[4][uint(index)]

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
		privVal.SignEntropy(newGen.baseConfig.ChainID(), &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare invalid validator signature", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)

		otherGen.sign()
		share := otherGen.entropyShares[2][uint(index)]
		// Alter signature message
		privVals[0].SignEntropy("wrong chain ID", &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare correct", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)

		otherGen.sign()
		share := otherGen.entropyShares[2][uint(index)]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 1)
	})
}

func TestEntropyGeneratorFlush(t *testing.T) {
	state, privVal := groupTestSetup(1)

	newGen := testEntropyGenerator()
	newGen.SetLogger(log.TestingLogger())

	aeonExecUnit := NewAeonExecUnit("test_keys/single_validator.txt")
	aeonDetails, _ := newAeonDetails(privVal[0], 1, state.Validators, aeonExecUnit, 1, 50)
	newGen.SetNextAeonDetails(aeonDetails)
	newGen.SetLastComputedEntropy(0, []byte("Test Entropy"))
	newGen.Start()

	assert.Eventually(t, func() bool { return newGen.getComputedEntropy(21) != nil }, 3*time.Second, 500*time.Millisecond)
	newGen.Stop()
	newGen.wait()
	assert.True(t, len(newGen.entropyShares) <= entropyHistoryLength+1)
	assert.True(t, len(newGen.entropyComputed) <= entropyHistoryLength+1)
}

func TestEntropyGeneratorApplyComputedEntropy(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	// Set up non-validator
	newGen := testEntropyGen(state.Validators, nil, -1)
	newGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
	newGen.setLastBlockHeight(1)
	newGen.Start()

	t.Run("applyEntropy old height", func(t *testing.T) {
		newGen.applyComputedEntropy(0, []byte("Fake signature"))
		assert.True(t, bytes.Equal(newGen.getComputedEntropy(0), []byte("Test Entropy")))
	})
	t.Run("applyEntropy height far ahead", func(t *testing.T) {
		newGen.applyComputedEntropy(3, []byte("Fake signature"))
		assert.True(t, newGen.getComputedEntropy(3) == nil)
	})
	t.Run("applyEntropy invalid entropy", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)

		otherGen.sign()
		share := otherGen.getEntropyShares(2)[uint(index)]
		newGen.applyComputedEntropy(2, []byte(share.SignatureShare))
		assert.True(t, newGen.getComputedEntropy(2) == nil)
	})
	t.Run("applyEntropy correct", func(t *testing.T) {
		index, _ := state.Validators.GetByAddress(privVals[0].GetPubKey().Address())
		otherGen := testEntropyGen(state.Validators, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)
		otherGen.Start()

		for _, val := range privVals {
			tempIndex, _ := state.Validators.GetByAddress(val.GetPubKey().Address())
			tempGen := testEntropyGen(state.Validators, val, tempIndex)
			tempGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
			tempGen.setLastBlockHeight(1)

			tempGen.sign()
			share := tempGen.getEntropyShares(2)[uint(tempIndex)]
			otherGen.applyEntropyShare(&share)
		}

		assert.Eventually(t, func() bool { return otherGen.getLastComputedEntropyHeight() >= 2 }, time.Second, 10*time.Millisecond)
		newGen.applyComputedEntropy(2, otherGen.getComputedEntropy(2))
		assert.True(t, bytes.Equal(newGen.getComputedEntropy(2), otherGen.getComputedEntropy(2)))
	})
}

func TestEntropyGeneratorChangeKeys(t *testing.T) {
	newGen := testEntropyGenerator()
	newGen.SetLogger(log.TestingLogger())
	newGen.SetNextAeonDetails(keylessAeonDetails(0, 4))

	assert.True(t, !newGen.isSigningEntropy())

	state, privVal := groupTestSetup(1)
	aeonExecUnit := NewAeonExecUnit("test_keys/single_validator.txt")
	aeonDetails, _ := newAeonDetails(privVal[0], 1, state.Validators, aeonExecUnit, 5, 50)
	newGen.SetNextAeonDetails(aeonDetails)

	newGen.Start()
	assert.Eventually(t, func() bool { return newGen.isSigningEntropy() }, time.Second, 100*time.Millisecond)
}

func groupTestSetup(nValidators int) (sm.State, []types.PrivValidator) {
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	return state, privVals
}

func testEntropyGen(validators *types.ValidatorSet, privVal types.PrivValidator, index int) *EntropyGenerator {
	newGen := testEntropyGenerator()
	newGen.SetLogger(log.TestingLogger())

	aeonExecUnit := NewAeonExecUnit("test_keys/non_validator.txt")
	if index >= 0 {
		aeonExecUnit = NewAeonExecUnit("test_keys/" + strconv.Itoa(int(index)) + ".txt")
	}
	aeonDetails, _ := newAeonDetails(privVal, 1, validators, aeonExecUnit, 1, 50)
	newGen.SetNextAeonDetails(aeonDetails)
	newGen.SetLastComputedEntropy(0, []byte("Test Entropy"))
	newGen.changeKeys()
	return newGen
}

func testEntropyGenerator() *EntropyGenerator {
	config := cfg.ResetTestRoot("entropy_generator_test")
	return NewEntropyGenerator(&config.BaseConfig, config.Beacon, 0)
}
