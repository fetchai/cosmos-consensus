package beacon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto/ed25519"
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

func TestDKGRunnerValidatorUpdates(t *testing.T) {
	nVals := 1
	dkgRunner, _ := testDKGRunners(nVals)
	dkgRunner[0].Start()

	// Wait for dkgRunner to set up subsription
	time.Sleep(time.Second)
	update := abci.ResponseEndBlock{
		ValidatorUpdates: []abci.ValidatorUpdate{{PubKey: types.TM2PB.PubKey(ed25519.GenPrivKey().PubKey()), Power: 20}},
	}
	err := dkgRunner[0].eventBus.PublishEventNewBlockHeader(types.EventDataNewBlockHeader{
		ResultEndBlock: update,
	})
	assert.True(t, err == nil)

	assert.Eventually(t, func() bool { return len(dkgRunner[0].validators.Validators) == 2 }, 10*time.Second, 100*time.Millisecond)
	dkgRunner[0].eventBus.Stop()
	dkgRunner[0].Stop()
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
		eventBus := types.NewEventBus()
		eventBus.SetLogger(logger.With("index", index, "module", "events"))
		eventBus.Start()
		dkgRunners[index].SetEventBus(eventBus)
	}
	return dkgRunners, fakeHandler
}
