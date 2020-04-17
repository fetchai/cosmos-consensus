package beacon

import (
	"sync"

	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
)

type DKGRunner struct {
	consensusConfig *cfg.ConsensusConfig
	chainID         string
	privVal         types.PrivValidator
	messageHandler  tx_extensions.SpecialTxHandler

	blockHeight int64
	validators  *types.ValidatorSet
	activeDKGs  map[int]*DistributedKeyGeneration

	dkgCompletionCallback func(aeon *aeonDetails)

	mtx sync.Mutex
}

func NewDKGRunner(config *cfg.ConsensusConfig, chain string, val types.PrivValidator,
	handler tx_extensions.SpecialTxHandler, height int64) *DKGRunner {
	return &DKGRunner{
		consensusConfig: config,
		chainID:         chain,
		privVal:         val,
		messageHandler:  handler,
		blockHeight:     height,
		activeDKGs:      make(map[int]*DistributedKeyGeneration),
	}
}

func (dkgRunner *DKGRunner) SetDKGCompletionCallback(callback func(aeon *aeonDetails)) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	dkgRunner.dkgCompletionCallback = callback
}

func (dkgRunner *DKGRunner) OnValidatorUpdates(height int64, updates []types.ValidatorUpdate) {
	dkgRunner.mtx.Lock()
	defer dkgRunner.mtx.Unlock()

	dkgRunner.vals.Update

}
