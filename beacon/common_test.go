package beacon

import (
	"fmt"
	"github.com/go-kit/kit/log/term"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
	dbm "github.com/tendermint/tm-db"
	"os"
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
		aeonExecUnits[i] = NewAeonExecUnit("/home/jenny/tendermint/beacon/test_keys/" + strconv.Itoa(int(i)) + ".txt")
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

		index, _ := state.Validators.GetByAddress(privVals[i].PubKey().Address())

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
	}
}

//-------------------------------------------------------------------------------
// genesis

func randValidator(randPower bool, minPower int64) (*types.Validator, crypto.PrivKey){
		newPrivKey := ed25519.GenPrivKey()
		votePower := minPower
		if randPower {
			votePower += int64(tmrand.Uint32())
		}
		pubKey := newPrivKey.PubKey()
		val := types.NewValidator(pubKey, votePower)
		return val, newPrivKey
}

func randGenesisDoc(numValidators int, randPower bool, minPower int64) (*types.GenesisDoc, []crypto.PrivKey) {
	validators := make([]types.GenesisValidator, numValidators)
	privKeys := make([]crypto.PrivKey, numValidators)
	for i := 0; i < numValidators; i++ {
		val, privKey := randValidator(randPower, minPower)
		validators[i] = types.GenesisValidator{
			PubKey: val.PubKey,
			Power:  val.VotingPower,
		}
		privKeys[i] = privKey
	}

	return &types.GenesisDoc{
		GenesisTime: tmtime.Now(),
		ChainID:     config.ChainID(),
		Validators:  validators,
		Entropy: []byte("Fetch.ai Test Genesis Entropy"),
	}, privKeys
}
