package beacon

import (
	"context"
	"sync"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
)

type DKGRunner struct {
	service.BaseService
	eventBus        *types.EventBus
	consensusConfig *cfg.ConsensusConfig
	chainID         string
	privVal         types.PrivValidator
	messageHandler  tx_extensions.MessageHandler

	height       int64
	validators   types.ValidatorSet
	activeDKG    *DistributedKeyGeneration
	completedDKG bool

	dkgCompletionCallback func(aeon *aeonDetails)

	mtx sync.Mutex
	// closed when shutting down to unblock send to full channel
	quit chan struct{}
}

func NewDKGRunner(config *cfg.ConsensusConfig, chain string, val types.PrivValidator,
	blockHeight int64, vals types.ValidatorSet) *DKGRunner {
	dkgRunner := &DKGRunner{
		consensusConfig: config,
		chainID:         chain,
		privVal:         val,
		height:          blockHeight,
		validators:      vals,
		completedDKG:    false,
		quit:            make(chan struct{}),
	}
	dkgRunner.BaseService = *service.NewBaseService(nil, "DKGRunner", dkgRunner)

	return dkgRunner
}

func (dkgRunner *DKGRunner) SetDKGCompletionCallback(callback func(aeon *aeonDetails)) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.dkgCompletionCallback = callback
}

func (dkgRunner *DKGRunner) SetEventBus(eventBus *types.EventBus) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.eventBus = eventBus
}

func (dkgRunner *DKGRunner) AttachMessageHandler(handler tx_extensions.MessageHandler) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()
	dkgRunner.messageHandler = handler
	// When DKG TXs are seen, they should call OnBlock
	dkgRunner.messageHandler.WhenChainTxSeen(dkgRunner.OnBlock)
}

func (dkgRunner *DKGRunner) OnStart() error {
	if dkgRunner.height%dkgRunner.consensusConfig.AeonLength == 0 {
		dkgRunner.startNewDKG()
	}
	if dkgRunner.eventBus != nil {
		err := dkgRunner.eventBus.Start()
		if err != nil {
			return err
		}
		// Start go routine for subscription
		go dkgRunner.validatorUpdatesRoutine()
	}
	return nil
}

func (dkgRunner *DKGRunner) OnStop() {
	close(dkgRunner.quit)
}

func (dkgRunner *DKGRunner) OnBlock(blockHeight int64, trxs []*types.DKGMessage) {
	dkgRunner.mtx.Lock()
	dkgRunner.height = blockHeight
	if dkgRunner.activeDKG != nil {
		dkgRunner.mtx.Unlock()
		dkgRunner.activeDKG.OnBlock(blockHeight, trxs)
	}
	// Trigger next dkg from message handler if no event bus for validator
	// updates
	if dkgRunner.eventBus == nil {
		dkgRunner.checkNextDKG()
	}
}

func (dkgRunner *DKGRunner) validatorUpdatesRoutine() {
	subscription, err := dkgRunner.eventBus.Subscribe(context.Background(), "dkg_runner", types.EventQueryNewBlockHeader)
	if err != nil {
		return
	}

	for {
		if !dkgRunner.IsRunning() {
			return
		}
		select {
		case msg := <-subscription.Out():
			header, ok := msg.Data().(*types.EventDataNewBlockHeader)
			if ok {
				abciValUpdates := header.ResultEndBlock.ValidatorUpdates
				validatorUpdates, _ := types.PB2TM.ValidatorUpdates(abciValUpdates)
				err := dkgRunner.validators.UpdateWithChangeSet(validatorUpdates)
				if err != nil {
					dkgRunner.Logger.Error("validatorUpdatesRoutine: update error %v", err.Error())
				}
			}
		case <-dkgRunner.quit:
			return
		}
		dkgRunner.checkNextDKG()
	}
}

func (dkgRunner *DKGRunner) checkNextDKG() {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	if dkgRunner.height%dkgRunner.consensusConfig.AeonLength == 0 {
		dkgRunner.startNewDKG()
	}
	// Reset completed DKG
	if dkgRunner.completedDKG {
		dkgRunner.activeDKG = nil
	}
	dkgRunner.completedDKG = false
}

func (dkgRunner *DKGRunner) startNewDKG() {
	aeon := int(dkgRunner.height % dkgRunner.consensusConfig.AeonLength)
	if dkgRunner.activeDKG != nil {
		dkgRunner.Logger.Error("startNewDKG: dkg already started", "aeon", aeon, "height", dkgRunner.height)
		return
	}
	if index, _ := dkgRunner.validators.GetByAddress(dkgRunner.privVal.GetPubKey().Address()); index < 0 {
		dkgRunner.Logger.Debug("startNewDKG: not in validators", "aeon", aeon, "height", dkgRunner.height)
		return
	}
	dkgRunner.Logger.Debug("startNewDKG: sucessful", "aeon", aeon, "height", dkgRunner.height)
	dkgRunner.activeDKG = NewDistributedKeyGeneration(dkgRunner.consensusConfig, dkgRunner.chainID,
		aeon, dkgRunner.privVal, dkgRunner.validators, dkgRunner.height+dkgRunner.consensusConfig.DKGResetDelay)
	dkgRunner.activeDKG.SetLogger(dkgRunner.Logger.With("dkgID", dkgRunner.activeDKG.dkgID))
	dkgRunner.activeDKG.SetSendMsgCallback(func(msg *types.DKGMessage) {
		dkgRunner.messageHandler.SubmitSpecialTx(msg)
	})
	dkgRunner.activeDKG.SetDkgCompletionCallback(func(keys *aeonDetails) {
		dkgRunner.completedDKG = true
		if dkgRunner.dkgCompletionCallback != nil {
			dkgRunner.dkgCompletionCallback(keys)
		}
	})
}
