package beacon

import (
	"fmt"
	"github.com/go-kit/kit/log/term"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
	dbm "github.com/tendermint/tm-db"
	"os"
	"sort"
	"strconv"
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

func randBeaconNet(testName string, configOpts ...func(*cfg.Config)) ([]*EntropyGenerator, cleanupFunc) {
	nValidators := 4
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)
	logger := beaconLogger()

	entropyGenerators := make([]*EntropyGenerator, nValidators)
	configRootDirs := make([]string, 0, nValidators)
	entropyChannels := make([]chan types.ComputedEntropy, nValidators)

	aeonExecUnits := setCrypto(nValidators)

	for i := 0; i < nValidators; i++ {
		stateDB := dbm.NewMemDB() // each state needs its own db
		state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
		thisConfig := ResetConfig(fmt.Sprintf("%s_%d", testName, i))
		configRootDirs = append(configRootDirs, thisConfig.RootDir)
		for _, opt := range configOpts {
			opt(thisConfig)
		}

		index, _ := state.Validators.GetByAddress(privVals[i].GetPubKey().Address())

		// Initialise entropy channel
		entropyChannels[i] = make(chan types.ComputedEntropy, EntropyChannelCapacity)

		entropyGenerators[i] = NewEntropyGenerator(logger, state.Validators, privVals[i], state.ChainID)
		entropyGenerators[i].SetLastComputedEntropy(types.ComputedEntropy{Height: types.GenesisHeight, GroupSignature: state.LastComputedEntropy})
		entropyGenerators[i].SetAeonKeys(aeonExecUnits[index])
		entropyGenerators[i].SetComputedEntropyChannel(entropyChannels[i])
	}

	return entropyGenerators, func() {
		for _, dir := range configRootDirs {
			os.RemoveAll(dir)
		}
		for j := 0; j < nValidators; j++ {
			close(entropyChannels[j])
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
		Entropy: "Fetch.ai Test Genesis Entropy",
	}, privValidators
}
