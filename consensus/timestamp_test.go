package consensus

import (
	"math/rand"
	"testing"
	"time"

	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/types"
)

// one byz val sends vote messages with conflicting timestamps
func TestReactorConflictingTimestamps(t *testing.T) {

	testCases := []struct {
		name    string
		msgtype types.SignedMsgType
	}{
		{"Prevotes with conflicting timestamps", types.PrevoteType},
		{"Precommits with conflicting timestamps", types.PrecommitType},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			N := 5
			css, cleanup := randConsensusNet(N, "consensus_reactor_test", newMockTickerFunc(true), newCounter)
			defer cleanup()

			for i := 0; i < N; i++ {
				ticker := NewTimeoutTicker()
				ticker.SetLogger(css[i].Logger)
				css[i].SetTimeoutTicker(ticker)

			}

			reactors, blocksSubs, eventBuses := startConsensusNet(t, css, N)

			// this val sends a two vote messages with different timestamps at each height
			byzValIdx := 0
			byzVal := css[byzValIdx]
			byzR := reactors[byzValIdx]

			byzVal.mtx.Lock()
			pv := byzVal.privValidator
			byzVal.doPrevote = func(height int64, round int) bool {
				invalidVoteFunc(t, height, round, byzVal, byzR.Switch, pv, tc.msgtype)
				return true
			}
			byzVal.mtx.Unlock()
			defer stopConsensusNet(log.TestingLogger(), reactors, eventBuses)

			// wait for a bunch of blocks
			// TODO: make this tighter by ensuring the halt happens by block 2
			for i := 0; i < 10; i++ {
				timeoutWaitGroup(t, N, func(j int) {
					<-blocksSubs[j].Out()
				}, css)
			}
		})
	}
}

func invalidVoteFunc(t *testing.T, height int64, round int, cs *State, sw *p2p.Switch, pv types.PrivValidator, voteType types.SignedMsgType) {
	go func() {
		cs.mtx.Lock()
		cs.privValidator = pv
		pubKey, err := cs.privValidator.GetPubKey()
		if err != nil {
			panic(err)
		}
		addr := pubKey.Address()
		valIndex, _ := cs.Validators.GetByAddress(addr)

		var blockHash []byte
		blockPartsHeader := types.PartSetHeader{}
		if cs.LockedBlock != nil {
			blockHash = cs.LockedBlock.Hash()
			blockPartsHeader = cs.LockedBlockParts.Header()
		} else if cs.ProposalBlock != nil {
			blockHash = cs.ProposalBlock.Hash()
			blockPartsHeader = cs.ProposalBlockParts.Header()
		}

		// vote1
		vote1 := &types.Vote{
			ValidatorAddress: addr,
			ValidatorIndex:   valIndex,
			Height:           cs.Height,
			Round:            cs.Round,
			Timestamp:        time.Now(),
			Type:             voteType,
			BlockID: types.BlockID{
				Hash:        blockHash,
				PartsHeader: blockPartsHeader,
			},
		}
		cs.privValidator.SignVote(cs.state.ChainID, vote1)
		// vote2
		vote2 := &types.Vote{
			ValidatorAddress: addr,
			ValidatorIndex:   valIndex,
			Height:           cs.Height,
			Round:            cs.Round,
			Timestamp:        cs.voteTime(),
			Type:             voteType,
			BlockID: types.BlockID{
				Hash:        blockHash,
				PartsHeader: blockPartsHeader,
			},
		}
		cs.privValidator.SignVote(cs.state.ChainID, vote2)
		cs.mtx.Unlock()

		peers := sw.Peers().List()
		for _, peer := range peers {
			if rand.Intn(2) == 0 {
				peer.Send(VoteChannel, cdc.MustMarshalBinaryBare(&VoteMessage{vote1}))
			} else {
				peer.Send(VoteChannel, cdc.MustMarshalBinaryBare(&VoteMessage{vote2}))
			}
		}
	}()
}
