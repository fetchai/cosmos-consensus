package beacon

import (
	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	config = ResetConfig("beacon_reactor_test")
	code := m.Run()
	os.RemoveAll(config.RootDir)
	os.Exit(code)
}

//----------------------------------------------
// in-process testnets

func startBeaconNet(t *testing.T, entropyGenerators []*EntropyGenerator, n int) (
	[]*Reactor,
	[]*EntropyGenerator,
) {
	reactors := make([]*Reactor, n)
	for i := 0; i < n; i++ {

		// Set up entropy generator
		reactors[i] = NewReactor(entropyGenerators[i])
		reactors[i].SetLogger(entropyGenerators[i].Logger)
	}
	// make connected switches and start all reactors
	p2p.MakeConnectedSwitches(config.P2P, n, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BEACON", reactors[i])
		s.SetLogger(reactors[i].Logger.With("module", "p2p"))
		return s
	}, p2p.Connect2Switches)

	return reactors, entropyGenerators
}

func stopBeaconNet(logger log.Logger, reactors []*Reactor) {
	logger.Info("stopBeaconNet", "n", len(reactors))
	for i, r := range reactors {
		logger.Info("stopBeaconNet: Stopping Reactor", "i", i)
		r.Switch.Stop()
	}
	logger.Info("stopBeaconNet: DONE", "n", len(reactors))
}

func TestReactorEntropy(t *testing.T) {
	entropyGenerators, cleanup := randBeaconNet("beacon_reactor_test")
	defer cleanup()
	N := len(entropyGenerators)
	reactors, entropyGenerators := startBeaconNet(t, entropyGenerators, N)
	defer stopBeaconNet(log.TestingLogger(), reactors)

	// Wait for everyone to generate 3 rounds of entropy
	time.Sleep(time.Second)
	for i := 0; i < N; i++ {
		_, err := entropyGenerators[i].GetEntropy(3)
		assert.True(t, err == nil)
	}
}
