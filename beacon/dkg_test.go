package beacon

import (
	"github.com/tendermint/tendermint/tx_extensions"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/libs/log"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tm-db"
)

type dkgFailure uint8

const (
	badShare dkgFailure = iota
	badCoefficient
	messagesWithInvalidIndex
	messagesWithInvalidCrypto
	qualMessagesWithInvalidCrypto
	emptyComplaintAnswer
	badQualCoefficient
	falseQualComplaint
	withholdReconstructionShare
	mutateData
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
	dkg.states[dkgStart].onExit = func() bool {
		dkg.Start()
		return false
	}
	// Trigger a failed transition
	dkg.checkTransition(dkg.startHeight)

	assert.True(t, !dkg.IsRunning())
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
			msg.Data = ""
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
			msg.Data = "changed data"
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

func TestDKGScenarios(t *testing.T) {
	testCases := []struct {
		testName       string
		failures       func([]*testNode)
		sendDuplicates bool
		nVals          int
		qualSize       int
		completionSize int
	}{
		{"All honest", func([]*testNode) {}, false, 4, 4, 4},
		{"Duplicate messages", func([]*testNode) {}, true, 4, 4, 4},
		{"Bad coefficient", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badCoefficient)
		}, false, 5, 4, 4},
		{"Bad share", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badShare)
		}, false, 5, 5, 5},
		{"False qual complaint", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, falseQualComplaint)
		}, false, 5, 5, 5},
		{"Bad share and no answer", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badShare)
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, emptyComplaintAnswer)
		}, false, 5, 4, 4},
		{"Messages with invalid index", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, messagesWithInvalidIndex)
		}, false, 5, 5, 5},
		{"Messages with invalid crypto", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, messagesWithInvalidCrypto)
		}, false, 5, 4, 4},
		{"Qual messages with invalid crypto", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, qualMessagesWithInvalidCrypto)
		}, false, 5, 5, 4},
		{"Mutate data", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, mutateData)
		}, false, 5, 4, 4},
		{"Restart DKG", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badShare)
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, emptyComplaintAnswer)
		}, false, 2, 2, 2},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			nodes := exampleDKGNetwork(tc.nVals, tc.sendDuplicates)

			// Create shared communication channel that represents the chain
			fakeHandler := tx_extensions.NewFakeMessageHandler()

			// Attach to all nodes
			for _, node := range nodes {
				node.dkg.AttachMessageHandler(fakeHandler)
			}

			// Set node failures
			tc.failures(nodes)

			// Start all nodes
			blockHeight := int64(10)
			for _, node := range nodes {
				node.dkg.OnBlock(blockHeight, []*types.DKGMessage{}) // OnBlock sends TXs to the chain
				node.clearTx()
			}

			// Wait until dkg has completed
			for nodes_finished := 0; nodes_finished < len(nodes); {
				fakeHandler.EndBlock(blockHeight) // All nodes get all TXs

				for _, node := range nodes {
					node.clearTx()
				}

				blockHeight++
				nodes_finished = 0

				for _, node := range nodes {
					if node.dkg.currentState == dkgFinish || node.dkg.dkgIteration >= 2 {
						nodes_finished++
					}
				}
			}

			// Check all outputs of expected completed nodes agree
			for index := 0; index < tc.completionSize; index++ {
				node := nodes[index]
				assert.Equal(t, int64(tc.qualSize), node.dkg.qual.Size(), "Wrong qual size")
				for index1 := 0; index1 < tc.completionSize; index1++ {
					node1 := nodes[index1]
					if index != index1 {
						assert.True(t, node.dkg.qual.Size() == node1.dkg.qual.Size())
						assert.True(t, node.dkg.output.GetGroup_public_key() == node1.dkg.output.GetGroup_public_key())
					}
				}
			}
		})
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
	dkg          *DistributedKeyGeneration
	currentTx    []*types.Tx
	nextTx       []*types.Tx
	failures     []dkgFailure
	sentBadShare bool
}

func newTestNode(privVal types.PrivValidator, vals *types.ValidatorSet, chainID string, sendDuplicates bool) *testNode {
	node := &testNode{
		dkg:          NewDistributedKeyGeneration(privVal, vals, 10, 0, chainID),
		currentTx:    make([]*types.Tx, 0),
		nextTx:       make([]*types.Tx, 0),
		failures:     make([]dkgFailure, 0),
		sentBadShare: false,
	}
	node.dkg.SetLogger(log.TestingLogger())

	return node
}

func (node *testNode) clearTx() {
	node.currentTx = node.nextTx
	node.nextTx = []*types.Tx{}
}

func (node *testNode) mutateTrx(trx *types.Tx) {
	if len(node.failures) != 0 {
		msg := &types.DKGMessage{}
		cdc.UnmarshalBinaryBare([]byte(*trx), msg)
		for i := 0; i < len(node.failures); i++ {
			if node.failures[i] == mutateData {
				msg.Data = "garbage"
				break
			}
			if node.failures[i] == badShare && msg.Type == types.DKGShare {
				if node.sentBadShare {
					continue
				} else {
					node.sentBadShare = true
				}
			}
			msg.Data = MutateMsg(msg.Data, FetchBeaconDKGMessageType(msg.Type), FetchBeaconFailure(node.failures[i]))
		}
		node.dkg.privValidator.SignDKGMessage(node.dkg.chainID, msg)
		*trx = types.Tx(cdc.MustMarshalBinaryBare(msg))
	}
}

func exampleDKGNetwork(nVals int, sendDuplicates bool) []*testNode {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)

	nodes := make([]*testNode, nVals)
	for i := 0; i < nVals; i++ {
		nodes[i] = newTestNode(privVals[i], state.Validators, genDoc.ChainID, sendDuplicates)
	}
	return nodes
}
