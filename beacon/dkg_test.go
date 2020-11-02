package beacon

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	dbm "github.com/tendermint/tm-db"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/mcl_cpp"
	tmnoise "github.com/tendermint/tendermint/noise"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
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
	withholdEncryptionKey
)

func init () {
	// Make sure to create the data dir if it is being used
	_ = os.Mkdir("data", 0777)
}

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
	assert.True(t, dkg.startHeight == oldStartHeight+oldDuration+keylessOffset+1)
	assert.True(t, dkg.stateDuration == oldStateDuration+int64(float64(oldStateDuration)*dkgIterationDurationMultiplier))
	assert.True(t, dkg.dkgIteration == 1)
}

func TestDKGCheckMessage(t *testing.T) {
	nodes := exampleDKGNetwork(4, 0, false)
	dkgToGenerateMsg := nodes[0].dkg
	dkgToProcessMsg := nodes[1].dkg

	testCases := []struct {
		testName   string
		changeMsg  func(*types.DKGMessage)
		passCheck  bool
		statusCode types.DKGMessageStatus
	}{
		{"Valid message", func(msg *types.DKGMessage) {}, true, types.OK},
		{"Fail validate basic", func(msg *types.DKGMessage) {
			msg.Data = ""
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false, types.Invalid},
		{"Incorrect dkg id", func(msg *types.DKGMessage) {
			msg.DKGID = dkgToGenerateMsg.dkgID + 1
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false, types.Invalid},
		{"Incorrect dkg iteration", func(msg *types.DKGMessage) {
			msg.DKGIteration = dkgToGenerateMsg.dkgIteration + 1
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false, types.Invalid},
		{"Not from validator", func(msg *types.DKGMessage) {
			privVal := types.NewMockPV()
			pubKey, _ := privVal.GetPubKey()
			msg.FromAddress = pubKey.Address()
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false, types.Invalid},
		{"Correct ToAddress", func(msg *types.DKGMessage) {
			pubKey, _ := dkgToProcessMsg.privValidator.GetPubKey()
			msg.ToAddress = pubKey.Address()
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, true, types.OK},
		{"Incorrect ToAddress", func(msg *types.DKGMessage) {
			privVal := types.NewMockPV()
			pubKey, _ := privVal.GetPubKey()
			msg.ToAddress = pubKey.Address()
			dkgToGenerateMsg.privValidator.SignDKGMessage(dkgToGenerateMsg.chainID, msg)
		}, false, types.Invalid},
		{"Incorrect Signature", func(msg *types.DKGMessage) {
			msg.Data = "changed data"
		}, false, types.Invalid},
		{"Message from self (not signed correctly)", func(msg *types.DKGMessage) {
			pubKey, _ := dkgToProcessMsg.privValidator.GetPubKey()
			msg.FromAddress = pubKey.Address()
		}, false, types.Invalid},
		{"DKG message with incorrect type id", func(msg *types.DKGMessage) {
			msg.Type = 999
		}, false, types.Invalid},
	}
	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			msg := dkgToGenerateMsg.newDKGMessage(types.DKGDryRun, "data", nil)
			tc.changeMsg(msg)
			index, val := dkgToProcessMsg.validators.GetByAddress(msg.FromAddress)
			status, err := dkgToProcessMsg.validateMessage(msg, index, val)
			assert.Equal(t, tc.passCheck, err == nil, "Unexpected error %v", err)
			assert.Equal(t, tc.statusCode, status)
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
			sigShares := mcl_cpp.NewIntStringMap()
			defer mcl_cpp.DeleteIntStringMap(sigShares)
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

// Test dkg submits evidence on failing at encryption and qual stage
func TestDKGEvidenceHandling(t *testing.T) {
	testCases := []struct {
		testName    string
		failures    func([]*testNode)
		nVals       int
		nSentries   int
		numEvidence int
	}{
		{"All honest", func([]*testNode) {}, 4, 1, 0},
		{"Fail encryption keys", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, withholdEncryptionKey)
		}, 4, 0, 1},
		{"Fail qual", func(nodes []*testNode) {
			nodes[len(nodes)-1].failures = append(nodes[len(nodes)-1].failures, badCoefficient)
			nodes[len(nodes)-2].failures = append(nodes[len(nodes)-2].failures, badCoefficient)
		}, 4, 0, 2},
	}
	for _, tc := range testCases {

		t.Run(tc.testName, func(t *testing.T) {
			nodes := exampleDKGNetwork(tc.nVals, tc.nSentries, false)
			cppLogger := NewNativeLoggingCollector(log.TestingLogger())
			cppLogger.Start()

			nTotal := tc.nVals + tc.nSentries
			honestEvidenceCount := 0
			nodes[0].dkg.evidenceHandler = func(*types.DKGEvidence) {
				honestEvidenceCount++
			}
			// Stop after first dkg failure
			for index := 0; index < nTotal; index++ {
				node := nodes[index]
				node.dkg.onFailState = func(blockHeight int64) {
					node.dkg.proceedToNextState(dkgFinish, true, blockHeight)
				}
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
					if node.dkg.dkgIteration >= 1 {
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

			// Check correct number of evidence was generated
			assert.Equal(t, tc.numEvidence, honestEvidenceCount)

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

	pubKey, _ := privVal.GetPubKey()

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
	baseConfig := cfg.TestBaseConfig()

	entropyParams := types.EntropyParams{
		AeonLength: 100,
	}
	dkg := NewDistributedKeyGeneration(config, &baseConfig, genDoc.ChainID, privVals[0], tmnoise.NewEncryptionKey(), 8, 1, *state.Validators, 20,
		entropyParams, nil)
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

func newTestNode(config *cfg.BeaconConfig, baseConfig *cfg.BaseConfig, chainID string, privVal types.PrivValidator,
	vals *types.ValidatorSet, sendDuplicates bool) *testNode {
	entropyParams := types.EntropyParams{
		AeonLength: 100,
	}
	node := &testNode{
		dkg: NewDistributedKeyGeneration(config, baseConfig, chainID, privVal, tmnoise.NewEncryptionKey(), 8, 1, *vals, 20,
			entropyParams, nil),
		currentMsgs:  make([]*types.DKGMessage, 0),
		nextMsgs:     make([]*types.DKGMessage, 0),
		failures:     make([]dkgFailure, 0),
		sentBadShare: false,
	}

	pubKey, _ := privVal.GetPubKey()

	index, _ := vals.GetByAddress(pubKey.Address())
	node.dkg.SetLogger(log.TestingLogger().With("dkgIndex", index))

	node.dkg.SetSendMsgCallback(func(msg *types.DKGMessage) {
		msg = node.mutateMsg(msg)
		if msg == nil {
			return
		}
		node.dkg.privValidator.SignDKGMessage(node.dkg.chainID, msg)
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

func (node *testNode) mutateMsg(msg *types.DKGMessage) *types.DKGMessage {
	if len(node.failures) != 0 {
		for i := 0; i < len(node.failures); i++ {
			if node.failures[i] == mutateData {
				msg.Data = "garbage"
				break
			}
			if node.failures[i] == withholdEncryptionKey && msg.Type == types.DKGEncryptionKey {
				return nil
			}
			if node.failures[i] == badShare && msg.Type == types.DKGShare {
				if node.sentBadShare {
					continue
				} else {
					node.sentBadShare = true
				}
			}
			msg.Data = mcl_cpp.MutateMsg(msg.Data, mcl_cpp.FetchBeaconDKGMessageType(msg.Type), mcl_cpp.FetchBeaconFailure(node.failures[i]))
		}
	}
	return msg
}

func exampleDKGNetwork(nVals int, nSentries int, sendDuplicates bool) []*testNode {
	genDoc, privVals := randGenesisDoc(nVals, false, 30)
	stateDB := dbm.NewMemDB() // each state needs its own db
	state, _ := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	config := cfg.TestBeaconConfig()
	baseConfig := cfg.TestBaseConfig()

	// make sure to remove the dkg file before each
	// test, and to disable recovery
	os.Remove(baseConfig.DkgBackupFile())

	nodes := make([]*testNode, nVals+nSentries)
	for i := 0; i < nVals; i++ {
		nodes[i] = newTestNode(config, &baseConfig, genDoc.ChainID, privVals[i], state.Validators, sendDuplicates)
		nodes[i].dkg.enableRecovery = false
	}
	for i := 0; i < nSentries; i++ {
		_, privVal := types.RandValidator(false, 10)
		nodes[nVals+i] = newTestNode(config, &baseConfig, genDoc.ChainID, privVal, state.Validators, sendDuplicates)
		nodes[nVals+i].dkg.enableRecovery = false
	}
	return nodes
}
func TestDKGRecovery(t *testing.T) {
	testCases := []struct {
		testName       string
		nVals          int
		nSentries      int
		fileRecovery   bool
	}{
		{"Crash during DKG, no file recovery", 1, 0, false},
		{"Crash during DKG, with file recovery", 1, 0, true},
	}
	for _, tc := range testCases {

		t.Run(tc.testName, func(t *testing.T) {
			nodes := exampleDKGNetwork(tc.nVals, tc.nSentries, false)
			cppLogger := NewNativeLoggingCollector(log.TestingLogger())
			cppLogger.Start()

			nTotal := tc.nVals + tc.nSentries
			outputs := make([]*aeonDetails, nTotal)
			secondOutputs := make([]*aeonDetails, nTotal)

			for index := 0; index < nTotal; index++ {
				output := &outputs[index]
				_ = output // dummy assignment
				nodes[index].dkg.SetDkgCompletionCallback(func(aeon *aeonDetails) {
					*output = aeon
				})
				nodes[index].dkg.enableRecovery = tc.fileRecovery
			}

			// Start all nodes
			blockHeight := int64(10)
			for _, node := range nodes {
				assert.True(t, !node.dkg.IsRunning())
				node.dkg.OnBlock(blockHeight, []*types.DKGMessage{}) // OnBlock sends TXs to the chain
				assert.True(t, node.dkg.IsRunning())
				node.clearMsgs()
			}

			var messagesInBlocks [][]*types.DKGMessage

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

				messagesInBlocks = append(messagesInBlocks, currentMsgs)

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

			// overwrite old dkgs
			for _, node := range nodes {
				node.dkg = node.dkg.ClearState()
			}

			aa := nodes[0].dkg.currentState

			fmt.Printf("thing %v", aa)

			// Now run again replaying the blocks (redirecting output), this should trigger the file recovery
			// redirect the output
			for index := 0; index < nTotal; index++ {
				output := &secondOutputs[index]
				_ = output // dummy assignment
				nodes[index].dkg.SetDkgCompletionCallback(func(aeon *aeonDetails) {
					*output = aeon
				})
				nodes[index].dkg.enableRecovery = tc.fileRecovery
			}

			fmt.Print("restarting...\n\n\n")

			// Restart/reset.
			// Note: why is this 10?
			blockHeight = int64(10)
			for _, node := range nodes {
				assert.True(t, !node.dkg.IsRunning())
				node.dkg.OnBlock(blockHeight, []*types.DKGMessage{}) // OnBlock sends TXs to the chain
				assert.True(t, node.dkg.IsRunning())
				node.clearMsgs()
			}

			// Send the old messages to the dkgs and get them to replay
			for _, messages := range messagesInBlocks {
				for _, node := range nodes {
					node.dkg.OnBlock(blockHeight, messages)
					node.clearMsgs()
				}
				blockHeight++
			}

			// Check the outputs match when recovery and not if not
			for index := 0; index < nTotal; index++ {
				originalPK := outputs[index].aeonExecUnit.PrivateKey()
				secondPK := secondOutputs[index].aeonExecUnit.PrivateKey()

				same := originalPK == secondPK

				assert.True(t, tc.fileRecovery == same)
			}

			cppLogger.Stop()
		})
	}
}
