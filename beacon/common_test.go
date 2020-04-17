package beacon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/go-kit/kit/log/term"

	abcicli "github.com/tendermint/tendermint/abci/client"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/consensus"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/mempool"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/store"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
	dbm "github.com/tendermint/tm-db"
)

const (
	testSubscriber = "test-client"
)

var config *cfg.Config

// A cleanupFunc cleans up any config / test files created for a particular
// test.
type cleanupFunc func()

func ensureDir(dir string, mode os.FileMode) {
	if err := tmos.EnsureDir(dir, mode); err != nil {
		panic(err)
	}
}

func ResetConfig(name string) *cfg.Config {
	return cfg.ResetTestRoot(name)
}

func beaconLogger() log.Logger {
	return log.TestingLoggerWithColorFn(func(keyvals ...interface{}) term.FgBgColor {
		for i := 0; i < len(keyvals)-1; i += 2 {
			if keyvals[i] == "validator" {
				return term.FgBgColor{Fg: term.Color(uint8(keyvals[i+1].(int) + 1))}
			}
		}
		return term.FgBgColor{}
	}).With("module", "beacon")
}

func setCrypto(nValidators int) []AeonExecUnit {
	InitialiseMcl()

	aeonExecUnits := make([]AeonExecUnit, nValidators)
	for i := 0; i < nValidators; i++ {
		aeonExecUnits[i] = NewAeonExecUnit("test_keys/" + strconv.Itoa(int(i)) + ".txt")
	}

	return aeonExecUnits
}

func newStateWithConfigAndBlockStore(
	thisConfig *cfg.Config,
	state sm.State,
	pv types.PrivValidator,
	blockDB dbm.DB,
) *consensus.State {
	// Get BlockStore
	blockStore := store.NewBlockStore(blockDB)

	// one for mempool, one for consensus
	mtx := new(sync.Mutex)
	app := abci.NewBaseApplication()
	proxyAppConnMem := abcicli.NewLocalClient(mtx, app)
	proxyAppConnCon := abcicli.NewLocalClient(mtx, app)

	// Make Mempool
	mempool := mempool.NewCListMempool(thisConfig.Mempool, proxyAppConnMem, 0)
	if thisConfig.Consensus.WaitForTxs() {
		mempool.EnableTxsAvailable()
	}

	// mock the evidence pool
	evpool := sm.MockEvidencePool{}

	// Make State
	stateDB := blockDB
	sm.SaveState(stateDB, state) //for save height 1's validators info
	blockExec := sm.NewBlockExecutor(stateDB, log.TestingLogger(), proxyAppConnCon, mempool, evpool)
	cs := consensus.NewState(thisConfig.Consensus, state, blockExec, blockStore, mempool, evpool)
	cs.SetLogger(log.TestingLogger().With("module", "consensus"))
	cs.SetPrivValidator(pv)

	return cs
}

func randBeaconAndConsensusNet(nValidators int, testName string, withConsensus bool) (css []*consensus.State, entropyGenerators []*EntropyGenerator, blockStores []*store.BlockStore, cleanup cleanupFunc) {
	entropyGenerators = make([]*EntropyGenerator, nValidators)
	blockStores = make([]*store.BlockStore, nValidators)
	logger := beaconLogger()
	configRootDirs := make([]string, 0, nValidators)
	aeonExecUnits := make([]AeonExecUnit, nValidators)
	entropyChannels := make([]chan types.ComputedEntropy, nValidators)

	if nValidators == 4 {
		aeonExecUnits = setCrypto(nValidators)
	} else if nValidators == 1 {
		aeonExecUnits[0] = NewAeonExecUnit("test_keys/single_validator.txt")
	} else {
		panic(fmt.Errorf("Invalid number of validators"))
	}
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)

	if withConsensus {
		css = make([]*consensus.State, nValidators)
	}

	for i := 0; i < nValidators; i++ {
		stateDB := dbm.NewMemDB() // each state needs its own db
		state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
		thisConfig := ResetConfig(fmt.Sprintf("%s_%d", testName, i))
		configRootDirs = append(configRootDirs, thisConfig.RootDir)

		index, _ := state.Validators.GetByAddress(privVals[i].GetPubKey().Address())
		blockStores[i] = store.NewBlockStore(stateDB)

		// Initialise entropy channel
		entropyChannels[i] = make(chan types.ComputedEntropy, thisConfig.Consensus.EntropyChannelCapacity)

		aeonDetails := NewAeonDetails(state.Validators, privVals[i], aeonExecUnits[index], 0, 50)
		entropyGenerators[i] = NewEntropyGenerator(&thisConfig.BaseConfig, thisConfig.Consensus, 0)
		entropyGenerators[i].SetLogger(logger)
		entropyGenerators[i].SetLastComputedEntropy(*types.NewComputedEntropy(0, state.LastComputedEntropy, true))
		entropyGenerators[i].SetAeonDetails(aeonDetails)
		entropyGenerators[i].SetComputedEntropyChannel(entropyChannels[i])

		if withConsensus {
			ensureDir(filepath.Dir(thisConfig.Consensus.WalFile()), 0700) // dir for wal
			css[i] = newStateWithConfigAndBlockStore(thisConfig, state, privVals[i], stateDB)
			css[i].SetLogger(logger.With("validator", i, "module", "consensus"))
			css[i].SetEntropyChannel(entropyChannels[i])
		}
	}
	return css, entropyGenerators, blockStores, func() {
		for _, dir := range configRootDirs {
			os.RemoveAll(dir)
		}
	}
}

//-------------------------------------------------------------------------------
// genesis

func randGenesisDoc(numValidators int, randPower bool, minPower int64) (*types.GenesisDoc, []types.PrivValidator) {
	validators := make([]types.GenesisValidator, numValidators)
	privValidators := make([]types.PrivValidator, numValidators)
	for i := 0; i < numValidators; i++ {
		val, privVal := types.RandValidator(randPower, minPower)
		validators[i] = types.GenesisValidator{
			PubKey: val.PubKey,
			Power:  val.VotingPower,
		}
		privValidators[i] = privVal
	}
	sort.Sort(types.PrivValidatorsByAddress(privValidators))

	return &types.GenesisDoc{
		GenesisTime: tmtime.Now(),
		ChainID:     config.ChainID(),
		Validators:  validators,
		Entropy:     "Fetch.ai Test Genesis Entropy",
	}, privValidators
}
