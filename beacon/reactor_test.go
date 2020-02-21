package beacon

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/p2p/mock"
)

func TestMain(m *testing.M) {
	config = ResetConfig("beacon_reactor_test")
	code := m.Run()
	os.RemoveAll(config.RootDir)
	os.Exit(code)
}

//----------------------------------------------
// in-process testnets

func startBeaconNet(t *testing.T, entropyGenerators []*EntropyGenerator, n int) []*Reactor {
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
	N := 4
	entropyGenerators, cleanup := randBeaconNet(N, "beacon_reactor_test")
	defer cleanup()
	entropyReactors := startBeaconNet(t, entropyGenerators, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

	// Wait for everyone to generate 3 rounds of entropy
	for i := 0; i < N; i++ {
		for {
			if entropyGenerators[i].entropyComputed[3] != nil {
				break
			} else {
				time.Sleep(2 * time.Millisecond)
			}
		}
	}
}

func TestReactorReceiveDoesNotPanicIfAddPeerHasntBeenCalledYet(t *testing.T) {
	entropyGenerators, cleanup := randBeaconNet(1, "beacon_reactor_test")
	defer cleanup()
	N := len(entropyGenerators)
	entropyReactors := startBeaconNet(t, entropyGenerators, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

	var (
		reactor = entropyReactors[0]
		peer    = mock.NewPeer(nil)
		msg     = cdc.MustMarshalBinaryBare(&HasComputedEntropy{Height: 1})
	)

	reactor.InitPeer(peer)

	// simulate switch calling Receive before AddPeer
	assert.NotPanics(t, func() {
		reactor.Receive(StateChannel, peer, msg)
		reactor.AddPeer(peer)
	})
}

func TestReactorReceivePanicsIfInitPeerHasntBeenCalledYet(t *testing.T) {
	entropyGenerators, cleanup := randBeaconNet(1, "beacon_reactor_test")
	defer cleanup()
	N := len(entropyGenerators)
	entropyReactors := startBeaconNet(t, entropyGenerators, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

	var (
		reactor = entropyReactors[0]
		peer    = mock.NewPeer(nil)
		msg     = cdc.MustMarshalBinaryBare(&HasComputedEntropy{Height: 1})
	)

	// we should call InitPeer here

	// simulate switch calling Receive before AddPeer
	assert.Panics(t, func() {
		reactor.Receive(StateChannel, peer, msg)
	})
}
