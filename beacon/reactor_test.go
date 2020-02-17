package beacon

import (
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
) {
	reactors := make([]*Reactor, n)
	for i := 0; i < n; i++ {

		// Set up entropy generator
		reactors[i] = NewReactor(entropyGenerators[i], false)
		reactors[i].SetLogger(entropyGenerators[i].Logger)
	}
	// make connected switches and start all reactors
	p2p.MakeConnectedSwitches(config.P2P, n, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BEACON", reactors[i])
		s.SetLogger(reactors[i].Logger.With("module", "p2p"))
		return s
	}, p2p.Connect2Switches)

	return reactors
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
	entropyReactors := startBeaconNet(t, entropyGenerators, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

	// Wait for everyone to generate 3 rounds of entropy
	for i := 0; i < N; i++ {
		for {
			_, err := entropyGenerators[i].GetEntropy(3)
			if err == nil {
				break
			} else {
				time.Sleep(2*time.Millisecond)
			}
		}
	}
}

