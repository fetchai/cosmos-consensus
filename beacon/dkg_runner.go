package beacon

import (
	"sync"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
)

type DKGRunner struct {
	service.BaseService
	consensusConfig *cfg.ConsensusConfig
	chainID         string
	privVal         types.PrivValidator
	messageHandler  tx_extensions.MessageHandler

	height       int64
	validators   *types.ValidatorSet
	activeDKG    *DistributedKeyGeneration
	completedDKG bool

	dkgCompletionCallback func(aeon *aeonDetails)

	mtx sync.Mutex
}

func NewDKGRunner(config *cfg.ConsensusConfig, chain string, val types.PrivValidator,
	handler tx_extensions.MessageHandler, blockHeight int64) *DKGRunner {
	dkgRunner := &DKGRunner{
		consensusConfig: config,
		chainID:         chain,
		privVal:         val,
		messageHandler:  handler,
		height:          blockHeight,
		completedDKG:    false,
	}
	dkgRunner.BaseService = *service.NewBaseService(nil, "DKGRunner", dkgRunner)

	// When DKG TXs are seen, they should call OnBlock
	dkgRunner.messageHandler.WhenChainTxSeen(dkgRunner.OnBlock)

	return dkgRunner
}

func (dkgRunner *DKGRunner) OnStart() error {
	if dkgRunner.height%dkgRunner.consensusConfig.AeonLength == 0 {
		dkgRunner.startNewDKG(dkgRunner.height)
	}
	return nil
}

func (dkgRunner *DKGRunner) SetDKGCompletionCallback(callback func(aeon *aeonDetails)) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	dkgRunner.dkgCompletionCallback = callback
}

func (dkgRunner *DKGRunner) OnBlock(blockHeight int64, trxs []*types.DKGMessage) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if dkgRunner.activeDKG != nil {
		dkgRunner.activeDKG.OnBlock(blockHeight, trxs)
	}
}

func (dkgRunner *DKGRunner) OnValidatorUpdates(height int64, updates []*types.Validator) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	err := dkgRunner.validators.UpdateWithChangeSet(updates)
	if err == nil && height%dkgRunner.consensusConfig.AeonLength == 0 {
		dkgRunner.startNewDKG(height)
	}
	// Reset completed DKG
	if dkgRunner.completedDKG {
		dkgRunner.activeDKG = nil
	}
	dkgRunner.completedDKG = false
}

func (dkgRunner *DKGRunner) startNewDKG(height int64) {
	aeon := int(height % dkgRunner.consensusConfig.AeonLength)
	if dkgRunner.activeDKG != nil {
		dkgRunner.Logger.Error("startNewDKG: dkg already started", "aeon", aeon, "height", height)
		return
	}
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.consensusConfig, dkgRunner.chainID,
		aeon, dkgRunner.privVal, dkgRunner.validators, height+dkgRunner.consensusConfig.DKGResetDelay)
	dkgRunner.activeDKG.SetSendMsgCallback(func(msg *types.DKGMessage) {
		dkgRunner.mtx.Lock()
		defer dkgRunner.mtx.Unlock()

		dkgRunner.messageHandler.SubmitSpecialTx(msg)
	})
	dkgRunner.activeDKG.SetDkgCompletionCallback(func(keys *aeonDetails) {
		dkgRunner.completedDKG = true
		dkgRunner.dkgCompletionCallback(keys)
	})
}
