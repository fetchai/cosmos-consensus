package beacon

import (
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/go-kit/kit/log/term"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	sm "github.com/tendermint/tendermint/state"
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

func randBeaconNet(nValidators int, testName string, configOpts ...func(*cfg.Config)) ([]*EntropyGenerator, cleanupFunc) {
	logger := beaconLogger()
	entropyGenerators := make([]*EntropyGenerator, nValidators)
	configRootDirs := make([]string, 0, nValidators)
	entropyChannels := make([]chan types.ComputedEntropy, nValidators)
	aeonExecUnits := make([]AeonExecUnit, nValidators)

	if nValidators == 4 {
		aeonExecUnits = setCrypto(nValidators)
	} else if nValidators == 1 {
		InitialiseMcl()
		aeonExecUnits[0] = NewAeonExecUnit("test_keys/single_validator.txt")
	} else {
		panic(fmt.Errorf("Invalid number of validators"))
	}
	genDoc, privVals := randGenesisDoc(nValidators, false, 30)

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

		aeonDetails := NewAeonDetails(state.Validators, privVals[i], aeonExecUnits[index])
		entropyGenerators[i] = NewEntropyGenerator(state.ChainID)
		entropyGenerators[i].SetLogger(logger)
		entropyGenerators[i].SetLastComputedEntropy(types.ComputedEntropy{Height: types.GenesisHeight, GroupSignature: state.LastComputedEntropy})
		entropyGenerators[i].SetAeonDetails(aeonDetails)
		entropyGenerators[i].SetComputedEntropyChannel(entropyChannels[i])
	}

	return entropyGenerators, func() {
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
