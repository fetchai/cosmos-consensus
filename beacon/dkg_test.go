package beacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

func TestDKGHelpers(t *testing.T) {
	dkg := exampleDKG(4)

	assert.True(t, dkg.duration() == int64(dkgFinish-1)*dkgTypicalStateDuration)
	// DKG is set to start at block height 10
	assert.False(t, dkg.stateExpired(dkg.startHeight-1))
	assert.True(t, dkg.stateExpired(dkg.startHeight))
	dkg.currentState = waitForCoefficientsAndShares
	assert.False(t, dkg.stateExpired(dkg.startHeight))
	assert.True(t, dkg.stateExpired(dkg.startHeight+dkgTypicalStateDuration))
	dkg.currentState = dkgFinish
	assert.False(t, dkg.stateExpired(dkg.startHeight+dkg.duration()-1))
	assert.True(t, dkg.stateExpired(dkg.startHeight+dkg.duration()))
}

func TestDKGCheckTransition(t *testing.T) {
	testCases := []struct {
		testName    string
		changeDKG   func(*DistributedKeyGeneration)
		blockHeight int64
		nextState   dkgState
	}{
		{"No state change", func(dkg *DistributedKeyGeneration) {}, 9, dkgStart},
		{"Proceed to next state", func(dkg *DistributedKeyGeneration) {}, 10, dkgStart + 1},
		{"Reset to start", func(dkg *DistributedKeyGeneration) {
			dkg.states[dkgStart].onExit = func() bool { return false }
		}, 10, dkgStart},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			dkg := exampleDKG(4)
			tc.changeDKG(dkg)
			dkg.checkTransition(tc.blockHeight)
			assert.Equal(t, tc.nextState, dkg.currentState, "dkg state not as expected")
		})
	}
}

func TestDKGReset(t *testing.T) {
	dkg := exampleDKG(4)
	oldStartHeight := dkg.startHeight
	dkg.states[dkgStart].onExit = func() bool { return false }
	// Trigger a failed transition
	dkg.checkTransition(dkg.startHeight)

	assert.True(t, dkg.startHeight == oldStartHeight+dkg.duration()+dkgResetWait)
	assert.True(t, dkg.dkgIteration == 1)
}

func TestDKGStartStop(t *testing.T) {
	dkg := exampleDKG(4)
	assert.True(t, !dkg.IsRunning())
	// Start dkg
	dkg.checkTransition(10)
	assert.True(t, dkg.IsRunning())
	// Finish dkg
	dkg.currentState = waitForReconstructionShares
	dkg.checkTransition(dkg.startHeight + dkg.duration())
	assert.True(t, !dkg.IsRunning())
}

func TestDKGCheckMessage(t *testing.T) {
	dkg := exampleDKG(4)

	testCases := []struct {
		testName  string
		changeMsg func(*types.DKGMessage)
		passCheck bool
	}{
		{"Valid message", func(msg *types.DKGMessage) {}, true},
		{"Fail validate basic", func(msg *types.DKGMessage) {
			msg.Data = []byte{}
			dkg.privValidator.SignDKGMessage(dkg.chainID, msg)
		}, false},
		{"Incorrect dkg id", func(msg *types.DKGMessage) {
			msg.DKGID = dkg.dkgID + 1
			dkg.privValidator.SignDKGMessage(dkg.chainID, msg)
		}, false},
		{"Incorrect dkg iteration", func(msg *types.DKGMessage) {
			msg.DKGIteration = dkg.dkgIteration + 1
			dkg.privValidator.SignDKGMessage(dkg.chainID, msg)
		}, false},
		{"Not from validator", func(msg *types.DKGMessage) {
			privVal := types.NewMockPV()
			msg.FromAddress = privVal.GetPubKey().Address()
			dkg.privValidator.SignDKGMessage(dkg.chainID, msg)
		}, false},
		{"Correct ToAddress", func(msg *types.DKGMessage) {
			msg.ToAddress = dkg.privValidator.GetPubKey().Address()
			dkg.privValidator.SignDKGMessage(dkg.chainID, msg)
		}, true},
		{"Incorrect ToAddress", func(msg *types.DKGMessage) {
			privVal := types.NewMockPV()
			msg.ToAddress = privVal.GetPubKey().Address()
			dkg.privValidator.SignDKGMessage(dkg.chainID, msg)
		}, false},
		{"Incorrect Signature", func(msg *types.DKGMessage) {
			msg.Data = []byte("changed data")
		}, false},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			msg := dkg.newDKGMessage(types.DKGShare, "data", nil)
			tc.changeMsg(msg)
			index, val := dkg.validators.GetByAddress(msg.FromAddress)
			err := dkg.checkMsg(msg, index, val)
			assert.Equal(t, tc.passCheck, err == nil, "Unexpected error %v", err)
		})
	}
}

func TestDKGSimple(t *testing.T) {
	nVals := 4
	nodes := exampleDKGNetwork(nVals)

	// Start all nodes
	for _, node := range nodes {
		node.dkg.OnBlock(node.dkg.startHeight, []*types.Tx{})
	}

OUTER_LOOP:
	for true {
		for index, node := range nodes {
			for index1, node1 := range nodes {
				if index1 != index {
					node1.dkg.OnBlock(node.dkg.startHeight, node.trxToBroadcast)
				}
			}
			node.clearTx()
		}
		for _, node := range nodes {
			if node.dkg.IsRunning() {
				continue OUTER_LOOP
			}
		}
		break
	}

	// Check all outputs agree
	for index, node := range nodes {
		assert.True(t, node.dkg.qual.Size() == int64(nVals))
		for index1, node1 := range nodes {
			if index != index1 {
				assert.True(t, node.dkg.qual.Size() == node1.dkg.qual.Size())
				assert.True(t, node.dkg.output.GetGroup_public_key() == node1.dkg.output.GetGroup_public_key())
			}
		}
	}

}

func exampleDKG(nVals int) *DistributedKeyGeneration {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	dkg := NewDistributedKeyGeneration(privVals[0], state.Validators, 10, 0, genDoc.ChainID)
	dkg.SetLogger(log.TestingLogger())
	return dkg
}

type testNode struct {
	dkg            *DistributedKeyGeneration
	trxToBroadcast []*types.Tx
}

func newTestNode(privVal types.PrivValidator, vals *types.ValidatorSet, chainID string) *testNode {
	node := &testNode{
		dkg:            NewDistributedKeyGeneration(privVal, vals, 10, 0, chainID),
		trxToBroadcast: make([]*types.Tx, 0),
	}
	node.dkg.SetLogger(log.TestingLogger())
	node.dkg.SetSendMsgCallback(func(trx *types.Tx) error {
		node.trxToBroadcast = append(node.trxToBroadcast, trx)
		return nil
	})

	return node
}

func (node *testNode) clearTx() {
	node.trxToBroadcast = []*types.Tx{}
}

func exampleDKGNetwork(nVals int) []*testNode {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)

	nodes := make([]*testNode, nVals)
	for i := 0; i < nVals; i++ {
		nodes[i] = newTestNode(privVals[i], state.Validators, genDoc.ChainID)
	}
	return nodes
}
