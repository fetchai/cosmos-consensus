package beacon

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/p2p/mock"
	sm "github.com/tendermint/tendermint/state"
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

func startBeaconNet(t *testing.T, entropyGenerators []*EntropyGenerator, blockStores []*store.BlockStore, n int, nStart int) []*Reactor {
	reactors := make([]*Reactor, n)

	for i := 0; i < n; i++ {
		fastSync := false
		if i >= nStart {
			fastSync = true
		}
		reactors[i] = NewReactor(entropyGenerators[i], fastSync, blockStores[i])
		reactors[i].SetLogger(entropyGenerators[i].Logger)
	}
	// make connected switches and start all reactors
	p2p.MakeConnectedSwitches(config.P2P, n, func(i int, s *p2p.Switch) *p2p.Switch {
		s.AddReactor("BEACON", reactors[i])
		return s
	}, p2p.Connect2Switches)

	return reactors
}

func stopBeaconNet(logger log.Logger, reactors []*Reactor) {
	logger.Info("stopBeaconNet", "n", len(reactors))

	for i, r := range reactors {
		logger.Info("stopBeaconNet: Stopping Switch", "i", i)
		r.Switch.Stop()
	}
	logger.Info("stopBeaconNet: DONE", "n", len(reactors))
}

func TestReactorEntropy(t *testing.T) {
	N := 4
	entropyGenerators, blockStores, cleanup := randBeaconNet(N, "beacon_reactor_test")
	defer cleanup()
	entropyReactors := startBeaconNet(t, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

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

func TestReactorReceiveDoesNotPanicIfAddPeerHasntBeenCalledYet(t *testing.T) {
	entropyGenerators, blockStores, cleanup := randBeaconNet(1, "beacon_reactor_test")
	defer cleanup()
	N := len(entropyGenerators)
	entropyReactors := startBeaconNet(t, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

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
	entropyGenerators, blockStores, cleanup := randBeaconNet(1, "beacon_reactor_test")
	defer cleanup()
	N := len(entropyGenerators)
	entropyReactors := startBeaconNet(t, entropyGenerators, blockStores, N, N)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

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

func TestReactorCatchupWithComputedEntropy(t *testing.T) {
	N := 4
	entropyGenerators, blockStores, cleanup := randBeaconNet(N, "beacon_reactor_test")
	defer cleanup()

	// Start all beacon reactors except one
	NStart := N - 1
	entropyReactors := startBeaconNet(t, entropyGenerators, blockStores, N, NStart)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

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
			assert.True(t, entropyGenerators[i].getLastComputedEntropyHeight() == types.GenesisHeight)
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
		s := sm.State{
			LastBlockHeight:     types.GenesisHeight,
			LastComputedEntropy: entropyGenerators[NStart].getComputedEntropy(types.GenesisHeight),
		}
		entropyReactors[NStart].SwitchToConsensus(s)
		for entropyGenerators[NStart].getLastComputedEntropyHeight() < entropyRounds-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}
func TestReactorCatchupWithBlocks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}
	N := 4
	entropyGenerators, blockStores, cleanup := randBeaconNet(N, "beacon_reactor_test")
	defer cleanup()

	// Start all beacon reactors except one
	NStart := N - 1
	entropyReactors := startBeaconNet(t, entropyGenerators, blockStores, N, NStart)
	defer stopBeaconNet(log.TestingLogger(), entropyReactors)

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
			delete(entropyGenerators[i].entropyComputed, round)
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
		s := sm.State{
			LastBlockHeight:     types.GenesisHeight,
			LastComputedEntropy: entropyGenerators[NStart].getComputedEntropy(types.GenesisHeight),
		}
		entropyReactors[NStart].SwitchToConsensus(s)
		for entropyGenerators[NStart].getLastComputedEntropyHeight() < entropyRounds-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// make a Commit with a single vote containing just the height and a timestamp
func makeTestCommit(height int64, timestamp time.Time) *types.Commit {
	commitSigs := []types.CommitSig{{
		BlockIDFlag:      types.BlockIDFlagCommit,
		ValidatorAddress: []byte("ValidatorAddress"),
		Timestamp:        timestamp,
		Signature:        []byte("Signature"),
	}}
	return types.NewCommit(height, 0, types.BlockID{}, commitSigs)
}

func makeTxs(height int64) (txs []types.Tx) {
	for i := 0; i < 10; i++ {
		txs = append(txs, types.Tx([]byte{byte(height), byte(i)}))
	}
	return txs
}

func makeBlock(height int64, state sm.State, lastCommit *types.Commit) *types.Block {
	block, _ := state.MakeBlock(height, makeTxs(height), lastCommit, nil, state.Validators.GetProposer().Address)
	return block
}
