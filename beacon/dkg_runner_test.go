package beacon

import (
	"testing"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/tx_extensions"
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

func testDKGRunners(nVals int) ([]*DKGRunner, tx_extensions.MessageHandler) {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	config := cfg.TestConsensusConfig()
	logger := log.TestingLogger()

	fakeHandler := tx_extensions.NewFakeMessageHandler()
	dkgRunners := make([]*DKGRunner, nVals)
	for index := 0; index < nVals; index++ {
		dkgRunners[index] = NewDKGRunner(config, "dkg_runner_test", privVals[index], 0, *state.Validators)
		dkgRunners[index].SetLogger(logger.With("index", index))
		dkgRunners[index].AttachMessageHandler(fakeHandler)
	}
	return dkgRunners, fakeHandler
}
