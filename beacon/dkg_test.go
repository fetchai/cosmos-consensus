package beacon

import (
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmnoise "github.com/tendermint/tendermint/noise"
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

	assert.True(t, dkg.duration() == int64(dkgFinish-1)*dkg.stateDuration)
	// DKG is set to start at block height 10
	assert.False(t, dkg.stateExpired(dkg.startHeight-1))
	assert.True(t, dkg.stateExpired(dkg.startHeight))
	dkg.currentState++
	assert.False(t, dkg.stateExpired(dkg.startHeight))
	assert.True(t, dkg.stateExpired(dkg.startHeight+dkg.stateDuration))
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
		{"No state change", func(dkg *DistributedKeyGeneration) {}, 7, dkgStart},
		{"Proceed to next state", func(dkg *DistributedKeyGeneration) {}, 10, dkgStart + 1},
		{"Skip to dry run", func(dkg *DistributedKeyGeneration) {
			dkg.currentState = dkgStart
			dkg.states[dkgStart].onExit = func() bool { return false }
		}, 10, waitForDryRun},
		{"Reset to start", func(dkg *DistributedKeyGeneration) {
			dkg.currentState = waitForDryRun
			dkg.states[waitForDryRun].onExit = func() bool {
				dkg.Start()
				return false
			}
		}, 60, dkgStart},
	}
	for _, tc := range testCases {
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
	oldDuration := dkg.duration()
	oldStateDuration := dkg.stateDuration
	dkg.states[waitForDryRun].onExit = func() bool {
		return false
	}
	dkg.Start()
	// Trigger a failed transition
	dkg.checkTransition(oldStartHeight + dkg.duration())

	assert.True(t, !dkg.IsRunning())
	assert.True(t, dkg.startHeight == oldStartHeight+oldDuration+dkgResetDelay)
	assert.True(t, dkg.stateDuration == oldStateDuration+int64(float64(oldStateDuration)*dkgIterationDurationMultiplier))
	assert.True(t, dkg.dkgIteration == 1)
}

func TestDKGCheckMessage(t *testing.T) {
	nodes := exampleDKGNetwork(4, 0, false)
	dkgToGenerateMsg := nodes[0].dkg
	dkgToProcessMsg := nodes[1].dkg

	testCases := []struct {
		testName  string
		changeMsg func(*types.DKGMessage)
		passCheck bool
	}{
		{"Valid message", func(msg *types.DKGMessage) {}, true},
		{"Fail validate basic", func(msg *types.DKGMessage) {
			msg.Data = ""
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false},
		{"Incorrect dkg id", func(msg *types.DKGMessage) {
			msg.DKGID = dkgToGenerateMsg.dkgID + 1
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false},
		{"Incorrect dkg iteration", func(msg *types.DKGMessage) {
			msg.DKGIteration = dkgToGenerateMsg.dkgIteration + 1
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false},
		{"Not from validator", func(msg *types.DKGMessage) {
			privVal := types.NewMockPV()
			pubKey := privVal.GetPubKey()
			msg.FromAddress = pubKey.Address()
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false},
		{"Correct ToAddress", func(msg *types.DKGMessage) {
			pubKey := dkgToProcessMsg.privValidator.GetPubKey()
			msg.ToAddress = pubKey.Address()
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, true},
		{"Incorrect ToAddress", func(msg *types.DKGMessage) {
			privVal := types.NewMockPV()
			pubKey := privVal.GetPubKey()
			msg.ToAddress = pubKey.Address()
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false},
		{"Incorrect Signature", func(msg *types.DKGMessage) {
			msg.Data = "changed data"
		}, false},
		{"Message from self", func(msg *types.DKGMessage) {
			pubKey := dkgToProcessMsg.privValidator.GetPubKey()
			msg.FromAddress = pubKey.Address()
		}, false},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			msg := dkgToGenerateMsg.newDKGMessage(types.DKGDryRun, "data", nil)
			tc.changeMsg(msg)
			index, val := dkgToProcessMsg.validators.GetByAddress(msg.FromAddress)
			err := dkgToProcessMsg.checkMsg(msg, index, val)
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
		nSentries      int
		qualSize       int
		completionSize int
	}{
		{"All honest", func([]*testNode) {}, false, 4, 0, 4, 4},
		{"With sentry", func([]*testNode) {}, false, 4, 1, 4, 4},
		{"Duplicate messages", func([]*testNode) {}, true, 4, 0, 4, 4},
		{"Bad coefficient", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badCoefficient)
		}, false, 5, 0, 4, 4},
		{"Bad share", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badShare)
		}, false, 5, 0, 5, 5},
		{"False qual complaint", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, falseQualComplaint)
		}, false, 5, 0, 5, 5},
		{"Bad share and no answer", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badShare)
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, emptyComplaintAnswer)
		}, false, 5, 0, 4, 4},
		{"Messages with invalid index", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, messagesWithInvalidIndex)
		}, false, 5, 0, 5, 5},
		{"Messages with invalid crypto", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, messagesWithInvalidCrypto)
		}, false, 5, 0, 4, 4},
		{"Qual messages with invalid crypto", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, qualMessagesWithInvalidCrypto)
		}, false, 5, 0, 5, 4},
		{"Mutate data", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, mutateData)
		}, false, 5, 0, 4, 4},
		{"Restart DKG", func(nodes []*testNode) {
			nodes[len(nodes)-2].failures = append(nodes[len(nodes)-2].failures, badShare)
			nodes[len(nodes)-2].failures = append(nodes[len(nodes)-2].failures, emptyComplaintAnswer)
		}, false, 2, 1, 2, 2},
	}
	for _, tc := range testCases {

		t.Run(tc.testName, func(t *testing.T) {
			nodes := exampleDKGNetwork(tc.nVals, tc.nSentries, tc.sendDuplicates)
			cppLogger := NewNativeLoggingCollector(log.TestingLogger())
			cppLogger.Start()

			nTotal := tc.nVals + tc.nSentries
			outputs := make([]*aeonDetails, nTotal)
			for index := 0; index < nTotal; index++ {
				output := &outputs[index]
				_ = output // dummy assignment
				nodes[index].dkg.SetDkgCompletionCallback(func(aeon *aeonDetails) {
					*output = aeon
				})
			}

			// Set node failures
			tc.failures(nodes)

			// Start all nodes
			blockHeight := int64(10)
			for _, node := range nodes {
				assert.True(t, !node.dkg.IsRunning())
				node.dkg.OnBlock(blockHeight, []*types.DKGMessage{}) // OnBlock sends TXs to the chain
				assert.True(t, node.dkg.IsRunning())
				node.clearMsgs()
			}

			for nodesFinished := 0; nodesFinished < nTotal; {
				blockHeight++
				currentMsgs := make([]*types.DKGMessage, 0)
				for _, node := range nodes {
					currentMsgs = append(currentMsgs, node.currentMsgs...)
				}
				for _, node := range nodes {
					node.dkg.OnBlock(blockHeight, currentMsgs)
					node.clearMsgs()
				}

				nodesFinished = 0
				for _, node := range nodes {
					if node.dkg.dkgIteration >= 2 {
						t.Log("Test failed: dkg iteration exceeded 1")
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
				for index := 0; index < nTotal; index++ {
					if nodes[index].dkg.IsRunning() {
						running++
					}
				}
				return running == 0
			}, 1*time.Second, 100*time.Millisecond)

			// Check outputs have been set
			for _, aeon := range outputs {
				if aeon == nil || aeon.aeonExecUnit == nil {
					t.Logf("Test failed: received nil dkg output")
					t.FailNow()
				}
			}

			// Check all outputs of expected completed nodes agree
			message := "TestMessage"
			sigShares := NewIntStringMap()
			defer DeleteIntStringMap(sigShares)
			for index := 0; index < tc.completionSize; index++ {
				node := nodes[index]
				signature := outputs[index].aeonExecUnit.Sign(message, uint(node.dkg.index()))
				for index1 := 0; index1 < nTotal; index1++ {
					if index != index1 {
						assert.True(t, outputs[index1].aeonExecUnit.Verify(message, signature, uint(node.dkg.index())))
					}
				}
				sigShares.Set(uint(node.dkg.index()), signature)
			}
			groupSig := outputs[0].aeonExecUnit.ComputeGroupSignature(sigShares)
			for index := 0; index < nTotal; index++ {
				assert.True(t, outputs[index].aeonExecUnit.VerifyGroupSignature(message, groupSig))
			}

			cppLogger.Stop()
		})
	}
}

// Test MaxDKGDataSize is large enough for the dry run messages for committee of size 200
func TestDKGMessageMaxDataSize(t *testing.T) {
	_, privVal := types.RandValidator(false, 10)
	aeonExecUnit := testAeonFromFile("test_keys/validator_0_of_200.txt")
	validators := types.ValidatorSet{Validators: make([]*types.Validator, 200)}
	aeonKeys := aeonDetails{
		validatorHeight: 0,
		aeonExecUnit:    aeonExecUnit,
		validators:      &validators,
		Start:           0,
		End:             100,
	}
	msgToSign := string(cdc.MustMarshalBinaryBare(aeonKeys.dkgOutput()))
	signature := aeonKeys.aeonExecUnit.Sign(msgToSign, 200)

	dryRun := DryRunSignature{
		PublicInfo:     *aeonKeys.dkgOutput(),
		SignatureShare: signature,
	}

	pubKey := privVal.GetPubKey()

	dkgMessage := types.DKGMessage{
		Type:         types.DKGDryRun,
		FromAddress:  pubKey.Address(),
		DKGID:        0,
		DKGIteration: 0,
		Data:         string(cdc.MustMarshalBinaryBare(&dryRun)),
	}
	privVal.SignDKGMessage("TestChain", &dkgMessage)
	assert.True(t, dkgMessage.ValidateBasic() == nil)
}

func exampleDKG(nVals int) *DistributedKeyGeneration {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	config := cfg.TestBeaconConfig()

	dkg := NewDistributedKeyGeneration(config, genDoc.ChainID, privVals[0], tmnoise.NewEncryptionKey(), 8, *state.Validators, 20, 100)
	dkg.SetLogger(log.TestingLogger())
	return dkg
}

type testNode struct {
	dkg          *DistributedKeyGeneration
	currentMsgs  []*types.DKGMessage
	nextMsgs     []*types.DKGMessage
	failures     []dkgFailure
	sentBadShare bool
}

func newTestNode(config *cfg.BeaconConfig, chainID string, privVal types.PrivValidator,
	vals *types.ValidatorSet, sendDuplicates bool) *testNode {
	node := &testNode{
		dkg:          NewDistributedKeyGeneration(config, chainID, privVal, tmnoise.NewEncryptionKey(), 8, *vals, 20, 100),
		currentMsgs:  make([]*types.DKGMessage, 0),
		nextMsgs:     make([]*types.DKGMessage, 0),
		failures:     make([]dkgFailure, 0),
		sentBadShare: false,
	}

	pubKey := privVal.GetPubKey()

	index, _ := vals.GetByAddress(pubKey.Address())
	node.dkg.SetLogger(log.TestingLogger().With("dkgIndex", index))

	node.dkg.SetSendMsgCallback(func(msg *types.DKGMessage) {
		node.mutateMsg(msg)
		node.nextMsgs = append(node.nextMsgs, msg)
		if sendDuplicates {
			node.nextMsgs = append(node.nextMsgs, msg)
		}
	})
	return node
}

func (node *testNode) clearMsgs() {
	node.currentMsgs = node.nextMsgs
	node.nextMsgs = make([]*types.DKGMessage, 0)
}

func (node *testNode) mutateMsg(msg *types.DKGMessage) {
	if len(node.failures) != 0 {
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
	}
}

func exampleDKGNetwork(nVals int, nSentries int, sendDuplicates bool) []*testNode {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	config := cfg.TestBeaconConfig()

	nodes := make([]*testNode, nVals+nSentries)
	for i := 0; i < nVals; i++ {
		nodes[i] = newTestNode(config, genDoc.ChainID, privVals[i], state.Validators, sendDuplicates)
	}
	for i := 0; i < nSentries; i++ {
		_, privVal := types.RandValidator(false, 10)
		nodes[nVals+i] = newTestNode(config, genDoc.ChainID, privVal, state.Validators, sendDuplicates)
	}
	return nodes
}
