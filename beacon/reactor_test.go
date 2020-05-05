package beacon

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/consensus"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/p2p/mock"
	"github.com/tendermint/tendermint/store"
	"github.com/tendermint/tendermint/types"
)

func TestMain(m *testing.M) {
	InitialiseMcl()
	config = cfg.ResetTestRoot("beacon_reactor_test")
	code := m.Run()
	os.RemoveAll(config.RootDir)
	os.Exit(code)
}

//----------------------------------------------
// in-process testnets

func startBeaconNet(t *testing.T, css []*consensus.ConsensusState, entropyGenerators []*EntropyGenerator, blockStores []*store.BlockStore, n int, nStart int) (
	consensusReactors []*consensus.ConsensusReactor,
	reactors []*Reactor,
	eventBuses []*types.EventBus,
) {
	reactors = make([]*Reactor, n)
	blocksSubs := make([]types.Subscription, 0)

	if css != nil {
		consensusReactors = make([]*consensus.ConsensusReactor, n)
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
			consensusReactors[i] = consensus.NewConsensusReactor(css[i], true) // so we dont start the consensus states
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

func stopBeaconNet(logger log.Logger, consensusReactors []*consensus.ConsensusReactor, eventBuses []*types.EventBus, reactors []*Reactor) {
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

	// Add second set of keys so entropy generations has patten ON, OFF, ON
	aeonKeys := setCrypto(N)
	for i := 0; i < N; i++ {
		existingAeon := entropyGenerators[i].aeon
		aeonDetails := newAeonDetails(existingAeon.privValidator, 1, existingAeon.validators, aeonKeys[i], 20, 29)
		entropyGenerators[i].SetNextAeonDetails(aeonDetails)
	}

	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for everyone to generate 3 rounds of entropy
	assert.Eventually(t, func() bool {
		for i := 0; i < N; i++ {
			if entropyGenerators[i].getLastBlockHeight() < 30 {
				return false
			}
		}
		return true
	}, 30*time.Second, 500*time.Millisecond)
	for i := 0; i < N; i++ {
		assert.True(t, entropyGenerators[i].getLastComputedEntropyHeight() == 29)
	}
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
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}
	N := 4
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(N, "beacon_reactor_test", true)
	defer cleanup()
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for everyone to generate 3 blocks
	for i := 0; i < N; i++ {
		for blockStores[i].LoadBlock(3) == nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
}
func TestReactorCatchupWithBlocks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}
	N := 4
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(N, "beacon_reactor_test", true)
	defer cleanup()

	// Start all beacon reactors except one
	NStart := N - 1
	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, NStart)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for reactors that started to generate 5 rounds of entropy
	entropyRounds := int64(5)
	for i := 0; i < NStart; i++ {
		for entropyGenerators[i].getLastComputedEntropyHeight() < entropyRounds-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Manually delete old entropy shares for these reactors
	for i := 0; i < N; i++ {
		for round := int64(0); round < entropyRounds; round++ {
			entropyGenerators[i].mtx.Lock()
			delete(entropyGenerators[i].entropyShares, round)
			entropyGenerators[i].mtx.Unlock()
		}
		if i == NStart {
			// Check that no entropy has been computed for stopped reactor
			assert.True(t, entropyGenerators[i].getLastComputedEntropyHeight() == 0)
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
		// set entropy channel to nil since we haven't started consensus reactor
		entropyReactors[NStart].entropyGen.computedEntropyChannel = nil
		entropyReactors[NStart].SwitchToConsensus(s)
		for entropyGenerators[NStart].getLastComputedEntropyHeight() < entropyRounds-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestReactorWithDKG(t *testing.T) {
	N := 4
	css, entropyGenerators, blockStores, cleanup := randBeaconAndConsensusNet(N, "beacon_reactor_test", false)
	defer cleanup()

	aeonStart := int64(20)

	dkgNodes := exampleDKGNetwork(N, false)

	for index := 0; index < N; index++ {
		entropyGen := entropyGenerators[index]
		// Reset entropy generator to state just before receiving first
		// dkg keys from genesus
		entropyGen.setLastBlockHeight(aeonStart - 1)
		entropyGen.entropyComputed = make(map[int64][]byte)
		entropyGen.lastComputedEntropyHeight = -1
		dkgNodes[index].dkg.SetDkgCompletionCallback(func(aeon *aeonDetails) {
			aeon.Start = aeonStart
			aeon.End = 30
			entropyGen.SetNextAeonDetails(aeon)
		})
	}

	// Start all nodes
	blockHeight := int64(10)
	for _, node := range dkgNodes {
		node.dkg.OnBlock(blockHeight, []*types.DKGMessage{}) // OnBlock sends TXs to the chain
		node.clearMsgs()
	}

	// Wait until dkg has completed
	for nodesFinished := 0; nodesFinished < N; {
		blockHeight++
		for index, node := range dkgNodes {
			for index1, node1 := range dkgNodes {
				if index1 != index {
					node1.dkg.OnBlock(blockHeight, node.currentMsgs)
				}
			}
		}
		for _, node := range dkgNodes {
			node.clearMsgs()
		}

		nodesFinished = 0

		for _, node := range dkgNodes {
			if node.dkg.dkgIteration >= 1 {
				t.Log("Test failed: dkg iteration exceeded 0")
				t.FailNow()
			}
			if node.dkg.currentState == dkgFinish {
				nodesFinished++
			}
		}
	}

	// Wait for all dkgs to stop running
	assert.Eventually(t, func() bool {
		running := 0
		for index := 0; index < N; index++ {
			if dkgNodes[index].dkg.IsRunning() {
				running++
			}
		}
		return running == 0
	}, 1*time.Second, 100*time.Millisecond)

	// Change keys over
	for _, entropyGen := range entropyGenerators {
		assert.True(t, entropyGen.nextAeon != nil)
		assert.True(t, entropyGen.changeKeys())
	}

	consensusReactors, entropyReactors, eventBuses := startBeaconNet(t, css, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), consensusReactors, eventBuses, entropyReactors)

	// Wait for everyone to generate 3 rounds of entropy
	assert.Eventually(t, func() bool {
		for i := 0; i < N; i++ {
			if entropyGenerators[i].getLastComputedEntropyHeight() < 3 {
				return false
			}
		}
		return true
	}, 3*time.Second, 100*time.Millisecond)
}
