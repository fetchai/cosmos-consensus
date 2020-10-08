package beacon

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	dbm "github.com/tendermint/tm-db"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
)

// Mock evidence pool for inactivity tracking
type mockEvidencePool struct {
	receivedEvidence []types.Evidence
}

func newMockEvidencePool() *mockEvidencePool {
	return &mockEvidencePool{
		receivedEvidence: make([]types.Evidence, 0),
	}
}

func (mep *mockEvidencePool) AddEvidence(ev types.Evidence) error {
	mep.receivedEvidence = append(mep.receivedEvidence, ev)
	return nil
}

func (mep *mockEvidencePool) PendingEvidence(int64) []types.Evidence {
	return mep.receivedEvidence
}

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
			aeonExecUnit := testAeonFromFile("test_keys/non_validator.txt")
			aeonDetails, _ := newAeonDetails(nil, 1, 1, state.Validators, aeonExecUnit, 1, 10)
			eg.SetNextAeonDetails(aeonDetails)
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			newGen := testEntropyGenerator("TestChain")
			tc.setup(newGen)
			assert.NotPanics(t, func() {
				newGen.Start()
			})
		})
	}
}

func TestEntropyGeneratorSetAeon(t *testing.T) {
	newGen := testEntropyGenerator("TestChain")
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
			aeonExecUnit := testAeonFromFile("test_keys/non_validator.txt")
			aeonDetails, _ := newAeonDetails(nil, 1, 1, state.Validators, aeonExecUnit, tc.start, tc.end)
			newGen.SetNextAeonDetails(aeonDetails)
			newGen.changeKeys()
			assert.Equal(t, newGen.isSigningEntropy(), tc.aeonSet)
		})
	}
}

func TestEntropyGeneratorNonValidator(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	newGen := testEntropyGen(state, nil, -1)

	// Does not panic if can not sign
	assert.NotPanics(t, func() {
		newGen.Start()
	})

	assert.True(t, newGen.getLastComputedEntropyHeight() == 0)

	// Give it entropy shares
	for i := 0; i < 3; i++ {
		privVal := privVals[i]
		pubKey, _ := privVal.GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		tempGen := testEntropyGen(state, privVal, index)
		tempGen.sign()

		share := tempGen.entropyShares[1][uint(index)]
		newGen.applyEntropyShare(&share)
	}

	assert.Eventually(t, func() bool { return newGen.getLastComputedEntropyHeight() == 1 }, time.Second, 10*time.Millisecond)
}

func TestEntropyGeneratorSign(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	pubKey, _ := privVals[0].GetPubKey()
	index, _ := state.Validators.GetByAddress(pubKey.Address())
	newGen := testEntropyGen(state, privVals[0], index)
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
	newGen := testEntropyGen(state, nil, -1)
	newGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
	newGen.setLastBlockHeight(1)

	t.Run("applyShare non-validator", func(t *testing.T) {
		_, privVal := types.RandValidator(false, 30)
		pubKey, _ := privVal.GetPubKey()
		aeonExecUnitInvalid := testAeonFromFile("test_keys/validator_" + strconv.Itoa(int(3)) + "_of_4.txt")
		message := string(tmhash.Sum(newGen.entropyComputed[1]))
		signature := aeonExecUnitInvalid.Sign(message, 3)
		share := types.EntropyShare{
			Height:         2,
			SignerAddress:  pubKey.Address(),
			SignatureShare: signature,
		}
		// Sign message
		privVal.SignEntropy(newGen.baseConfig.ChainID(), &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare old height", func(t *testing.T) {
		pubKey, _ := privVals[0].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		otherGen := testEntropyGen(state, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)

		otherGen.sign()
		share := otherGen.entropyShares[1][uint(index)]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[1]) == 0)
	})
	t.Run("applyShare height far ahead", func(t *testing.T) {
		pubKey, _ := privVals[0].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		otherGen := testEntropyGen(state, privVals[0], index)
		otherGen.SetLastComputedEntropy(3, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(3)

		otherGen.sign()
		share := otherGen.entropyShares[4][uint(index)]

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[4]) == 0)
	})
	t.Run("applyShare invalid share", func(t *testing.T) {
		privVal := privVals[0]
		pubKey, _ := privVal.GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		aeonExecUnitInvalid := testAeonFromFile("test_keys/validator_" + strconv.Itoa(int((index+1)%3)) + "_of_4.txt")
		message := string(tmhash.Sum(newGen.entropyComputed[1]))
		signature := aeonExecUnitInvalid.Sign(message, uint(index))

		share := types.EntropyShare{
			Height:         2,
			SignerAddress:  pubKey.Address(),
			SignatureShare: signature,
		}
		// Sign message
		privVal.SignEntropy(newGen.baseConfig.ChainID(), &share)

		newGen.applyEntropyShare(&share)
		assert.True(t, len(newGen.entropyShares[2]) == 0)
	})
	t.Run("applyShare invalid validator signature", func(t *testing.T) {
		pubKey, _ := privVals[0].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		otherGen := testEntropyGen(state, privVals[0], index)
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
		pubKey, _ := privVals[0].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		otherGen := testEntropyGen(state, privVals[0], index)
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

	newGen := testEntropyGenerator(state.ChainID)
	newGen.SetLogger(log.TestingLogger())

	aeonExecUnit := testAeonFromFile("test_keys/single_validator.txt")
	aeonDetails, _ := newAeonDetails(privVal[0], 1, 1, state.Validators, aeonExecUnit, 1, 50)
	newGen.SetNextAeonDetails(aeonDetails)
	newGen.SetLastComputedEntropy(0, []byte("Test Entropy"))
	newGen.Start()

	assert.Eventually(t, func() bool { return newGen.getComputedEntropy(21) != nil }, 3*time.Second, 500*time.Millisecond)
	newGen.Stop()
	// Wait for compute entropy routine to exit
	time.Sleep(time.Second)
	assert.True(t, len(newGen.entropyShares) <= entropyHistoryLength+1)
	assert.True(t, len(newGen.entropyComputed) <= entropyHistoryLength+1)
}

func TestEntropyGeneratorApplyComputedEntropy(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	// Set up non-validator
	newGen := testEntropyGen(state, nil, -1)
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
		pubKey, _ := privVals[0].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		otherGen := testEntropyGen(state, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)

		otherGen.sign()
		share := otherGen.getEntropyShares(2)[uint(index)]
		newGen.applyComputedEntropy(2, []byte(share.SignatureShare))
		assert.True(t, newGen.getComputedEntropy(2) == nil)
	})
	t.Run("applyEntropy correct", func(t *testing.T) {
		pubKey, _ := privVals[0].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		otherGen := testEntropyGen(state, privVals[0], index)
		otherGen.SetLastComputedEntropy(1, []byte("Test Entropy"))
		otherGen.setLastBlockHeight(1)
		otherGen.Start()

		for _, val := range privVals {
			pubKey, _ := val.GetPubKey()
			tempIndex, _ := state.Validators.GetByAddress(pubKey.Address())
			tempGen := testEntropyGen(state, val, tempIndex)
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
	newGen := testEntropyGenerator("TestChain")
	newGen.SetLogger(log.TestingLogger())
	newGen.SetNextAeonDetails(keylessAeonDetails(1, 1, 0, 4))

	assert.True(t, !newGen.isSigningEntropy())

	state, privVal := groupTestSetup(1)
	aeonExecUnit := testAeonFromFile("test_keys/single_validator.txt")
	aeonDetails, _ := newAeonDetails(privVal[0], 1, 1, state.Validators, aeonExecUnit, 5, 50)
	newGen.SetNextAeonDetails(aeonDetails)

	newGen.Start()
	assert.Eventually(t, func() bool { return newGen.isSigningEntropy() }, time.Second, 100*time.Millisecond)
}

func TestEntropyResetActivityTracking(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)

	testCases := []struct {
		testName             string
		privVal              types.PrivValidator
		mapNil               bool
		activityTrackingSize int
	}{
		{"Sentry", nil, true, 0},
		{"Validator", privVals[0], false, 3},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			index := -1
			if tc.privVal != nil {
				pubKey, _ := tc.privVal.GetPubKey()
				index, _ = state.Validators.GetByAddress(pubKey.Address())
			}
			newGen := testEntropyGen(state, tc.privVal, index)

			assert.Equal(t, tc.mapNil, newGen.activityTracking == nil)
			if !tc.mapNil {
				assert.Equal(t, tc.activityTrackingSize, len(newGen.activityTracking))
				_, haveIndex := newGen.activityTracking[uint(index)]
				assert.False(t, haveIndex)
				assert.True(t, newGen.aeonEntropyParams != nil)
			}
		})
	}
}

func TestEntropyActivityTracking(t *testing.T) {
	nValidators := 4
	state, privVals := groupTestSetup(nValidators)
	entropyParams := state.ConsensusParams.Entropy
	windowSize := entropyParams.InactivityWindowSize
	threshold := int64(float64(entropyParams.RequiredActivityPercentage*windowSize) * 0.01)

	// Set up validator
	pubKey, _ := privVals[0].GetPubKey()
	index, _ := state.Validators.GetByAddress(pubKey.Address())

	testCases := []struct {
		testName        string
		sharesReceived  int64
		entropyHeight   int64
		entropyEnabled  bool
		pendingEvidence int
	}{
		{"Less than window size", 10, 10, true, 0},
		{"Slash all but one", threshold - 1, windowSize, false, 2},
		{"Slash everyone", threshold - 1, windowSize, true, 3},
		{"Does not double slash", threshold + 1, windowSize + 1, true, 2},
		{"Slash new misbehaviour", threshold, windowSize + 1, true, 3},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			newGen := testEntropyGen(state, privVals[0], index)

			otherIndex := uint((index + 1) % nValidators)
			for i := int64(0); i < tc.entropyHeight; i++ {
				if i < tc.sharesReceived {
					newGen.entropyShares[i+1] = make(map[uint]types.EntropyShare)
					newGen.entropyShares[i+1][otherIndex] = types.EntropyShare{}
				}
				enabled := true
				if i == tc.entropyHeight-1 {
					enabled = tc.entropyEnabled
				}
				newGen.updateActivityTracking(types.NewChannelEntropy(i+1, types.BlockEntropy{}, enabled, nil))
			}

			evidence := newGen.evpool.PendingEvidence(0)
			assert.Equal(t, tc.pendingEvidence, len(evidence))
			blockEntropy := newGen.blockEntropy(newGen.aeon.Start + 1)
			blockEntropy.NextAeonStart = 1
			for _, ev := range evidence {
				beaconInactivityEvidence, err := ev.(*types.BeaconInactivityEvidence)
				assert.True(t, err)
				assert.Nil(t, beaconInactivityEvidence.Verify(state.ChainID, blockEntropy, state.Validators, state.ConsensusParams.Entropy))
			}
		})
	}
}

func groupTestSetup(nValidators int) (sm.State, []types.PrivValidator) {
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	return state, privVals
}

func testEntropyGen(state sm.State, privVal types.PrivValidator, index int) *EntropyGenerator {
	newGen := testEntropyGenerator(state.ChainID)
	newGen.SetLogger(log.TestingLogger())
	sm.SaveState(newGen.stateDB, state)

	aeonExecUnit := testAeonFromFile("test_keys/non_validator.txt")
	if index >= 0 {
		aeonExecUnit = testAeonFromFile("test_keys/validator_" + strconv.Itoa(int(index)) + "_of_4.txt")
	}
	aeonDetails, _ := newAeonDetails(privVal, 1, 1, state.Validators, aeonExecUnit, 1, 50)
	newGen.SetNextAeonDetails(aeonDetails)
	newGen.SetLastComputedEntropy(0, []byte("Test Entropy"))
	newGen.changeKeys()
	return newGen
}

func testEntropyGenerator(chainID string) *EntropyGenerator {
	config := cfg.ResetTestRoot("entropy_generator_test")
	stateDB := dbm.NewMemDB() // each state needs its own db
	return NewEntropyGenerator(chainID, &config.BaseConfig, config.Beacon, 0, newMockEvidencePool(), stateDB)
}
