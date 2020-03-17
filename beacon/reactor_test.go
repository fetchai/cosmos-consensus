package beacon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/consensus"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/p2p/mock"
	"github.com/tendermint/tendermint/store"
	"github.com/tendermint/tendermint/types"
)

func TestMain(m *testing.M) {
	InitialiseMcl()
	config = ResetConfig("beacon_reactor_test")
	code := m.Run()
	os.RemoveAll(config.RootDir)
	os.Exit(code)
}

//----------------------------------------------
// in-process testnets

func startBeaconNet(t *testing.T, css []*consensus.State, entropyGenerators []*EntropyGenerator, blockStores []*store.BlockStore, n int, nStart int) (
	consensusReactors []*consensus.Reactor,
	reactors []*Reactor,
	eventBuses []*types.EventBus,
) {
	reactors = make([]*Reactor, n)
	blocksSubs := make([]types.Subscription, 0)

	if css != nil {
		consensusReactors = make([]*consensus.Reactor, n)
		eventBuses = make([]*types.EventBus, n)
	}

	for i := 0; i < n; i++ {
		// Set up entropy generator
		fastSync := false
		if css != nil {
			fastSync = true
		}

		reactors[i] = NewReactor(entropyGenerators[i], fastSync, blockStores[i])
		reactors[i].SetLogger(entropyGenerators[i].Logger)

		if css != nil {
			consensusReactors[i] = consensus.NewReactor(css[i], true) // so we dont start the consensus states
			consensusReactors[i].SetLogger(css[i].Logger)

			// eventBus is already started with the cs
			eventBuses[i] = types.NewEventBus()
			eventBuses[i].SetLogger(log.TestingLogger().With("module", "events"))
			eventBuses[i].Start()
			css[i].SetEventBus(eventBuses[i])
			consensusReactors[i].SetEventBus(eventBuses[i])

			blocksSub, err := eventBuses[i].Subscribe(context.Background(), testSubscriber, types.EventQueryNewBlock)
			require.NoError(t, err)
			blocksSubs = append(blocksSubs, blocksSub)
		}
	}
	// make connected switches and start all reactors
	p2p.MakeConnectedSwitches(config.P2P, n, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BEACON", reactors[i])
		if css != nil {
			s.AddReactor("CONSENSUS", consensusReactors[i])
		}
		return s
	}, p2p.Connect2Switches)

	if css != nil {
		for i := 0; i < nStart; i++ {
			s := css[i].GetState()
			consensusReactors[i].SwitchToConsensus(s, 0)
		}
	}

	return consensusReactors, reactors, eventBuses
}

func stopBeaconNet(logger log.Logger, consensusReactors []*consensus.Reactor, eventBuses []*types.EventBus, reactors []*Reactor) {
	logger.Info("stopBeaconNet", "n", len(reactors))

	if eventBuses != nil {
		for i, b := range eventBuses {
			logger.Info("stopConsensusNet: Stopping eventBus", "i", i)
			b.Stop()
		}
	}

	for i, r := range reactors {
		logger.Info("stopBeaconNet: Stopping Switch", "i", i)
		r.Switch.Stop()
	}
	logger.Info("stopBeaconNet: DONE", "n", len(reactors))
}

func TestReactorEntropy(t *testing.T) {
	N := 4
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(N, "beacon_reactor_test", false)
	defer cleanup()
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for everyone to generate 3 rounds of entropy
	assert.Eventually(t, func() bool {
		for i := 0; i < N; i++ {
			if entropyGenerators[i].entropyComputed[3] != nil {
				return false
			}
		}
		return true
	}, 3*time.Second, 100*time.Millisecond)
}

func TestReactorReceiveDoesNotPanicIfAddPeerHasntBeenCalledYet(t *testing.T) {
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(1, "beacon_reactor_test", false)
	defer cleanup()
	N := len(entropyGenerators)
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	var (
		reactor = entropyReactors[0]
		peer    = mock.NewPeer(nil)
		msg     = cdc.MustMarshalBinaryBare(&NewEntropyHeightMessage{Height: 1})
	)

	reactor.InitPeer(peer)

	// simulate switch calling Receive before AddPeer
	assert.NotPanics(t, func() {
		reactor.Receive(StateChannel, peer, msg)
		reactor.AddPeer(peer)
	})
}

func TestReactorReceivePanicsIfInitPeerHasntBeenCalledYet(t *testing.T) {
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(1, "beacon_reactor_test", false)
	defer cleanup()
	N := len(entropyGenerators)
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	var (
		reactor = entropyReactors[0]
		peer    = mock.NewPeer(nil)
		msg     = cdc.MustMarshalBinaryBare(&NewEntropyHeightMessage{Height: 1})
	)

	// simulate switch calling Receive before AddPeer
	assert.Panics(t, func() {
		reactor.Receive(StateChannel, peer, msg)
	})
}

func TestReactorWithConsensus(t *testing.T) {
	N := 4
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(N, "beacon_reactor_test", true)
	defer cleanup()
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for everyone to generate 3 blocks
	assert.Eventually(t, func() bool {
		for i := 0; i < N; i++ {
			if blockStores[i].LoadBlock(3) == nil {
				return false
			}
		}
		return true
	}, 5*time.Second, 100*time.Millisecond)
}
func TestReactorCatchupWithBlocks(t *testing.T) {
	N := 4
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(N, "beacon_reactor_test", true)
	defer cleanup()

	// Start all beacon reactors except one
	NStart := N - 1
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, NStart)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for reactors that started to generate 11 rounds of entropy
	entropyRounds := int64(11)
	assert.Eventually(t, func() bool {
		for i := 0; i < NStart; i++ {
			if entropyGenerators[i].entropyComputed[entropyRounds-1] == nil {
				return false
			}
		}
		return true
	}, 2*time.Duration(entropyRounds)*time.Second, 500*time.Millisecond)

	// Manually delete old entropy shares for these reactors
	for i := 0; i < N; i++ {
		for round := int64(0); round < entropyRounds; round++ {
			delete(entropyGenerators[i].entropyShares, round)
			if i == NStart && round > 0 {
				// Check that no entropy has been computed for stopped reactor
				assert.True(t, entropyGenerators[i].entropyComputed[round] == nil)
			}
		}
		if i != NStart && NStart < N {
			// Check that peer state from stopped node is at 0
			stoppedID := entropyReactors[NStart].Switch.NodeInfo().ID()
			peerState, ok := entropyReactors[i].Switch.Peers().Get(stoppedID).Get("BeaconReactor.peerState").(*PeerState)
			assert.True(t, ok)
			assert.True(t, peerState.getLastComputedEntropyHeight() == types.GenesisHeight)
		}
	}

	// Now start remaining reactor and wait for it to catch up
	if NStart < N {
		s := css[NStart].GetState()
		entropyReactors[NStart].SwitchToConsensus(s)
		// set entropy channel to nil since we haven't started consensus reactor
		entropyReactors[NStart].entropyGen.computedEntropyChannel = nil
		assert.Eventually(t, func() bool {
			return entropyGenerators[NStart].entropyComputed[entropyRounds-1] != nil
		}, time.Duration(entropyRounds)*time.Second, 500*time.Millisecond)
		// Wait for computeEntropyRoutine to recognise the change
		assert.Eventually(t, func() bool {
			return entropyGenerators[NStart].getLastComputedEntropyHeight() >= entropyRounds-1
		}, 2*computeEntropySleepDuration, 10*time.Millisecond)
	}
}
