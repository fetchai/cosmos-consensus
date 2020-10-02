package beacon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/go-kit/kit/log/term"

	dbm "github.com/tendermint/tm-db"

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

func setCrypto(nValidators int) []BaseAeon {
	InitialiseMcl()

	aeonExecUnits := make([]BaseAeon, nValidators)
	for i := 0; i < nValidators; i++ {
		aeonExecUnits[i] = testAeonFromFile("test_keys/validator_" + strconv.Itoa(int(i)) + "_of_4.txt")
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
	mempool := mempool.NewCListMempool(thisConfig.Mempool, proxyAppConnMem, 0, nil)
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
	aeonExecUnits := make([]BaseAeon, nValidators)

	if nValidators == 4 {
		aeonExecUnits = setCrypto(nValidators)
	} else if nValidators == 1 {
		aeonExecUnits[0] = testAeonFromFile("test_keys/single_validator.txt")
	} else {
		panic(fmt.Errorf("Invalid number of validators"))
	}
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)

	var entropyChannels []chan types.ChannelEntropy
	if withConsensus {
		entropyChannels = make([]chan types.ChannelEntropy, nValidators)
		css = make([]*consensus.State, nValidators)
	}

	for i := 0; i < nValidators; i++ {
		stateDB := dbm.NewMemDB() // each state needs its own db
		state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
		thisConfig := cfg.ResetTestRoot(fmt.Sprintf("%s_%d", testName, i))
		configRootDirs = append(configRootDirs, thisConfig.RootDir)

		pubKey, _ := privVals[i].GetPubKey()
		index, _ := state.Validators.GetByAddress(pubKey.Address())
		blockStores[i] = store.NewBlockStore(stateDB)
		evpool := sm.MockEvidencePool{}

		aeonDetails, _ := newAeonDetails(privVals[i], 1, 1, state.Validators, aeonExecUnits[index], 1, 9)
		entropyGenerators[i] = NewEntropyGenerator(&thisConfig.BaseConfig, thisConfig.Beacon, 0, evpool, stateDB)
		entropyGenerators[i].SetLogger(logger)
		entropyGenerators[i].SetLastComputedEntropy(0, state.LastComputedEntropy)
		entropyGenerators[i].SetNextAeonDetails(aeonDetails)

		if withConsensus {
			ensureDir(filepath.Dir(thisConfig.Consensus.WalFile()), 0700) // dir for wal
			// Initialise entropy channel
			entropyChannels[i] = make(chan types.ChannelEntropy, thisConfig.Beacon.EntropyChannelCapacity)

			css[i] = newStateWithConfigAndBlockStore(thisConfig, state, privVals[i], stateDB)
			css[i].SetLogger(logger.With("validator", i, "module", "consensus"))
			css[i].SetEntropyChannel(entropyChannels[i])
			entropyGenerators[i].SetEntropyChannel(entropyChannels[i])
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

	// Make inactivity window smaller for tests
	params := types.DefaultConsensusParams()
	params.Entropy.InactivityWindowSize = 50

	return &types.GenesisDoc{
		GenesisTime:     tmtime.Now(),
		ChainID:         config.ChainID(),
		ConsensusParams: params,
		Validators:      validators,
		Entropy:         "Fetch.ai Test Genesis Entropy",
	}, privValidators
}
