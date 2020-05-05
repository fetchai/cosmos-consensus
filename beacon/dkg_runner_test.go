package beacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

func TestDKGRunnerOnGenesis(t *testing.T) {
	nVals := 4
	dkgRunners, fakeHandler := testDKGRunners(nVals)

	dkgsCompleted := 0
	for index := 0; index < nVals; index++ {
		dkgRunners[index].SetDKGCompletionCallback(func(*aeonDetails) {
			dkgsCompleted++
		})
	}

	for _, runner := range dkgRunners {
		runner.Start()
	}

	blockHeight := int64(1)
	for dkgsCompleted < nVals {
		fakeHandler.EndBlock(blockHeight)
		blockHeight++
	}

	for _, runner := range dkgRunners {
		runner.Stop()
	}
}

func TestDKGRunnerFindValidators(t *testing.T) {
	nVals := 1
	dkgRunner, _ := testDKGRunners(nVals)
	dkgRunner[0].Start()
	dkgRunner[0].OnBlock(1, []byte{}, nil)
	dkgRunner[0].OnBlock(2, []byte{}, nil)
	dkgRunner[0].OnBlock(3, []byte{}, nil)

	// Create state after execution of block 1
	newVals := make([]*types.Validator, 2)
	newVals[0], _ = types.RandValidator(false, 20)
	newVals[1], _ = types.RandValidator(false, 20)
	newState := sm.State{
		LastBlockHeight:             1,
		NextValidators:              types.NewValidatorSet(newVals),
		LastHeightValidatorsChanged: 3,
	}
	sm.SaveState(dkgRunner[0].stateDB, newState)

	savedVals, err := sm.LoadValidators(dkgRunner[0].stateDB, 3)
	assert.True(t, err == nil)
	assert.Equal(t, 2, len(savedVals.Validators))

	vals := dkgRunner[0].findValidators(3)
	index, _ := vals.GetByAddress(newVals[0].PubKey.Address())
	assert.True(t, index >= 0)
	dkgRunner[0].Stop()
}

func testDKGRunners(nVals int) ([]*DKGRunner, tx_extensions.MessageHandler) {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	config := cfg.TestConsensusConfig()
	logger := log.TestingLogger()

	fakeHandler := tx_extensions.NewFakeMessageHandler()
	dkgRunners := make([]*DKGRunner, nVals)
	for index := 0; index < nVals; index++ {
		dkgRunners[index] = NewDKGRunner(config, "dkg_runner_test", stateDB, privVals[index], 0)
		dkgRunners[index].SetLogger(logger.With("index", index))
		dkgRunners[index].AttachMessageHandler(fakeHandler)
	}
	return dkgRunners, fakeHandler
}
