package beacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmnoise "github.com/tendermint/tendermint/noise"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

func TestDKGRunnerOnGenesis(t *testing.T) {
	nVals := 4
	nSentries := 1
	nTotal := nVals + nSentries
	dkgRunners, fakeHandler := testDKGRunners(nVals, nSentries)

	dkgsCompleted := 0
	for index := 0; index < nTotal; index++ {
		dkgRunners[index].SetDKGCompletionCallback(func(*aeonDetails) {
			dkgsCompleted++
		})
	}

	for _, runner := range dkgRunners {
		runner.Start()
	}

	blockHeight := int64(1)
	for dkgsCompleted < nTotal {
		fakeHandler.EndBlock(blockHeight)
		blockHeight++
		for _, runner := range dkgRunners {
			if runner.activeDKG != nil && runner.activeDKG.dkgIteration > 2 {
				t.FailNow()
			}
		}
	}

	for _, runner := range dkgRunners {
		runner.Stop()
	}
}

func TestDKGRunnerFindValidators(t *testing.T) {
	nVals := 1
	dkgRunner, _ := testDKGRunners(nVals, 0)
	dkgRunner[0].Start()
	dkgRunner[0].OnBlock(1, []byte{}, nil)
	dkgRunner[0].OnBlock(2, []byte{}, nil)
	dkgRunner[0].OnBlock(3, []byte{}, nil)

	// Create state after execution of block 1
	newVals := make([]*types.Validator, 2)
	newVals[0], _ = types.RandValidator(false, 20)
	newVals[1], _ = types.RandValidator(false, 20)
	// Need to create and save two states because validator updates
	// are delayed by two blocks
	newState := sm.State{
		LastBlockHeight:             1,
		NextValidators:              types.NewValidatorSet(newVals),
		LastHeightValidatorsChanged: 3,
	}
	newState2 := sm.State{
		LastBlockHeight:                  2,
		LastHeightConsensusParamsChanged: 3,
	}
	newState2.ConsensusParams.Entropy.AeonLength = int64(120)
	sm.SaveState(dkgRunner[0].stateDB, newState)
	sm.SaveState(dkgRunner[0].stateDB, newState2)

	savedVals, err := sm.LoadValidators(dkgRunner[0].stateDB, 3)
	assert.True(t, err == nil)
	assert.Equal(t, 2, len(savedVals.Validators))
	savedParams, err := sm.LoadConsensusParams(dkgRunner[0].stateDB, 3)
	assert.True(t, err == nil)
	assert.Equal(t, int64(120), savedParams.Entropy.AeonLength)

	vals, aeonLength := dkgRunner[0].findValidatorsAndParams(3)
	index, _ := vals.GetByAddress(newVals[0].PubKey.Address())
	assert.True(t, index >= 0)
	assert.True(t, aeonLength == 120)
}

func testDKGRunners(nVals int, nSentries int) ([]*DKGRunner, tx_extensions.MessageHandler) {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	config := cfg.TestBeaconConfig()
	logger := log.TestingLogger()

	fakeHandler := tx_extensions.NewFakeMessageHandler()
	dkgRunners := make([]*DKGRunner, nVals+nSentries)
	for index := 0; index < nVals; index++ {
		dkgRunners[index] = NewDKGRunner(config, "dkg_runner_test", stateDB, privVals[index], tmnoise.NewEncryptionKey(), 0)
		dkgRunners[index].SetLogger(logger.With("index", index))
		dkgRunners[index].AttachMessageHandler(fakeHandler)
	}
	for index := 0; index < nSentries; index++ {
		_, privVal := types.RandValidator(false, 10)
		dkgRunners[nVals+index] = NewDKGRunner(config, "dkg_runner_test", stateDB, privVal, tmnoise.NewEncryptionKey(), 0)
		dkgRunners[nVals+index].SetLogger(logger.With("index", -1))
		dkgRunners[nVals+index].AttachMessageHandler(fakeHandler)
	}
	return dkgRunners, fakeHandler
}
