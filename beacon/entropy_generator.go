package beacon

import (
	"fmt"
	"sync"
	"time"

	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

var (
	// EntropyChannelCapacity is number of ComputedEntropy that channel can hold
	EntropyChannelCapacity = 3
)

// EntropyGenerator holds DKG keys for computing entropy and computes entropy shares
// and entropy for dispatching along channel
type EntropyGenerator struct {
	service.BaseService

	proxyMtx sync.Mutex

	threshold                 int
	entropyShares             map[int64]map[int]types.EntropyShare
	entropyComputed           map[int64]types.ThresholdSignature
	lastComputedEntropyHeight int64

	// Channel for sending off entropy for receiving elsewhere
	computedEntropyChannel chan<- types.ComputedEntropy

	// To be safe, need to store set of validators who can participate in DRB here to avoid
	// possible problems with validator set changing allowed by Tendermint
	privValidator types.PrivValidator
	Validators    *types.ValidatorSet
	aeonExecUnit  AeonExecUnit

	// For signing entropy messages
	chainID string
}

// NewEntropyGenerator creates new entropy generator with validator information
func NewEntropyGenerator(
	validators *types.ValidatorSet, newPrivValidator types.PrivValidator, newChainID string) *EntropyGenerator {
	if validators == nil {
		panic(fmt.Sprintf("NewEntropyGenerator with nil validator set"))
	}
	es := &EntropyGenerator{
		entropyShares:             make(map[int64]map[int]types.EntropyShare),
		lastComputedEntropyHeight: -1, // value is invalid and requires last entropy to be set
		entropyComputed:           make(map[int64]types.ThresholdSignature),
		privValidator:             newPrivValidator,
		Validators:                validators,
		chainID:                   newChainID,
	}

	es.threshold = es.Validators.Size()/2 + 1
	es.BaseService = *service.NewBaseService(nil, "EntropyGenerator", es)
	return es
}

// SetLastComputedEntropy sets the most recent entropy from catchup
func (entropyGenerator *EntropyGenerator) SetLastComputedEntropy(entropy types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.entropyComputed[entropy.Height] != nil {
		entropyGenerator.Logger.Error("Attempt to reset existing entropy")
		return
	}
	entropyGenerator.entropyComputed[entropy.Height] = entropy.GroupSignature
	// If new entropy is more recent that our last computed entropy then update
	if entropy.Height > entropyGenerator.lastComputedEntropyHeight {
		entropyGenerator.lastComputedEntropyHeight = entropy.Height
	}
}

// SetAeonKeys sets the DKG keys for computing DRB
func (entropyGenerator *EntropyGenerator) SetAeonKeys(aeonKeys AeonExecUnit) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.aeonExecUnit = aeonKeys
}

// SetComputedEntropyChannel sets the channel along which entropy should be dispatched
func (entropyGenerator *EntropyGenerator) SetComputedEntropyChannel(entropyChannel chan<- types.ComputedEntropy) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.computedEntropyChannel == nil {
		entropyGenerator.computedEntropyChannel = entropyChannel
	}
}

// SetLogger implements Service.
func (entropyGenerator *EntropyGenerator) SetLogger(l log.Logger) {
	entropyGenerator.BaseService.Logger = l
}

// OnStart generates entropy from the last computed entropy height
func (entropyGenerator *EntropyGenerator) OnStart() error {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	if entropyGenerator.aeonExecUnit == nil {
		panic(fmt.Errorf("OnStart with no active execution unit"))
	}

	if entropyGenerator.lastComputedEntropyHeight < types.GenesisHeight {
		panic(fmt.Sprintf("OnStart without setting last computed entropy"))
	}

	entropyGenerator.sign(entropyGenerator.lastComputedEntropyHeight)
	// Start go routine for computing threshold signature
	go entropyGenerator.computeEntropyRoutine()
	return nil
}

// OnStop is noop
func (entropyGenerator *EntropyGenerator) OnStop() {
}

// ApplyEntropyShare processes entropy share from reactor
func (entropyGenerator *EntropyGenerator) applyEntropyShare(share *types.EntropyShare) {
	entropyGenerator.proxyMtx.Lock()
	defer entropyGenerator.proxyMtx.Unlock()

	entropyGenerator.Logger.Debug("ApplyEntropyShare", "height", share.Height, "from", share.SignerAddress)
	index, validator := entropyGenerator.Validators.GetByAddress(share.SignerAddress)
	err := entropyGenerator.validInputs(share.Height, index)
	if err != nil {
		entropyGenerator.Logger.Debug(err.Error())
		return
	}

	// Verify signature on message
	verifySig := validator.PubKey.VerifyBytes(share.SignBytes(entropyGenerator.chainID), share.Signature)
	if !verifySig {
		entropyGenerator.Logger.Error("invalid validator signature on entropy share", "validator", share.SignerAddress, "index", index)
		return
	}

	// Verify share
	message := string(tmhash.Sum(entropyGenerator.entropyComputed[share.Height-1]))
	if !entropyGenerator.aeonExecUnit.Verify(message, share.SignatureShare, uint64(index)) {
		entropyGenerator.Logger.Error("invalid entropy share", "validator", share.SignerAddress, "index", index)
		return
	}

	entropyGenerator.Logger.Info("New entropy share received", "height", share.Height, "validator index", index)
	if entropyGenerator.entropyShares[share.Height] == nil {
		entropyGenerator.entropyShares[share.Height] = make(map[int]types.EntropyShare)
	}

	entropyGenerator.entropyShares[share.Height][index] = share.Copy()
	return
}

// GetEntropyShares gets entropy shares at a particular height
func (entropyGenerator *EntropyGenerator) getEntropyShares(height int64) map[int]types.EntropyShare {
	return entropyGenerator.entropyShares[height]
}

func (entropyGenerator *EntropyGenerator) validInputs(height int64, index int) error {
	if index < 0 {
		return fmt.Errorf("invalid validator index %v", index)
	}
	if height <= entropyGenerator.lastComputedEntropyHeight {
		return fmt.Errorf("already computed entropy at height %v", height)
	}
	if height > entropyGenerator.lastComputedEntropyHeight+1 {
		return fmt.Errorf("missing previous entropy at height %v", height-1)
	}
	if len(entropyGenerator.entropyShares[height][index].SignatureShare) != 0 {
		return fmt.Errorf("already have entropy share at height %v index %v", height, index)
	}
	return nil
}

func (entropyGenerator *EntropyGenerator) sign(height int64) {
	if !entropyGenerator.aeonExecUnit.CanSign() {
		entropyGenerator.Logger.Debug("node can not sign entropy - no dkg private key")
		return
	}
	// Node which can sign on entropy should also be a validator
	if entropyGenerator.privValidator == nil {
		panic(fmt.Sprintf("entropy generator with invalid privValidator"))
	}
	index, _ := entropyGenerator.Validators.GetByAddress(entropyGenerator.privValidator.GetPubKey().Address())
	err := entropyGenerator.validInputs(height+1, index)
	if err != nil {
		if index < 0 {
			panic(fmt.Sprintf("entropy generator with invalid privValidator"))
		}
		entropyGenerator.Logger.Debug(err.Error())
		return
	}

	entropyGenerator.Logger.Debug("sign block entropy", "height", height, "nodeAddress", entropyGenerator.privValidator.GetPubKey().Address())

	message := string(tmhash.Sum(entropyGenerator.entropyComputed[height]))
	signature := entropyGenerator.aeonExecUnit.Sign(message)
	if !entropyGenerator.aeonExecUnit.Verify(message, signature, uint64(index)) {
		entropyGenerator.Logger.Error("sign on block entropy generated invalid signature", "height", height)
		return
	}

	// Insert own signature into entropy shares
	if entropyGenerator.entropyShares[height+1] == nil {
		entropyGenerator.entropyShares[height+1] = make(map[int]types.EntropyShare)
	}
	share := types.EntropyShare{
		Height:         height + 1,
		SignerAddress:  entropyGenerator.privValidator.GetPubKey().Address(),
		SignatureShare: signature,
	}
	// Sign message
	err = entropyGenerator.privValidator.SignEntropy(entropyGenerator.chainID, &share)
	if err != nil {
		entropyGenerator.Logger.Error(err.Error())
		return
	}
	entropyGenerator.entropyShares[height+1][index] = share
}

func (entropyGenerator *EntropyGenerator) computeEntropyRoutine() {
	for {
		entropyGenerator.proxyMtx.Lock()
		haveNewEntropy := entropyGenerator.receivedEntropyShare()
		entropyGenerator.proxyMtx.Unlock()

		if haveNewEntropy {
			// Need to unlock before dispatching to entropy channel otherwise deadlocks
			if entropyGenerator.computedEntropyChannel != nil {
				entropyGenerator.computedEntropyChannel <- types.ComputedEntropy{
					Height:         entropyGenerator.lastComputedEntropyHeight,
					GroupSignature: entropyGenerator.entropyComputed[entropyGenerator.lastComputedEntropyHeight],
				}
			}

			// Continue onto the next random value
			entropyGenerator.proxyMtx.Lock()
			entropyGenerator.sign(entropyGenerator.lastComputedEntropyHeight)
			entropyGenerator.proxyMtx.Unlock()
		}
		time.Sleep(ComputeEntropySleepDuration)
	}
}

func (entropyGenerator *EntropyGenerator) receivedEntropyShare() bool {

	height := entropyGenerator.lastComputedEntropyHeight + 1
	if entropyGenerator.entropyComputed[height] != nil {
		entropyGenerator.Logger.Error("lastComputedEntropyHeight not updated!")
		entropyGenerator.lastComputedEntropyHeight++
		return false
	}
	if len(entropyGenerator.entropyShares[height]) >= entropyGenerator.threshold {
		message := string(tmhash.Sum(entropyGenerator.entropyComputed[height-1]))
		signatureShares := NewIntStringMap()
		defer DeleteIntStringMap(signatureShares)

		for key, share := range entropyGenerator.entropyShares[height] {
			signatureShares.Set(key, share.SignatureShare)
		}
		groupSignature := entropyGenerator.aeonExecUnit.ComputeGroupSignature(signatureShares)
		if !entropyGenerator.aeonExecUnit.VerifyGroupSignature(message, groupSignature) {
			entropyGenerator.Logger.Error("entropy_generator.VerifyGroupSignature == false")
			return false
		}
		entropyGenerator.Logger.Info("New entropy computed", "height", height)
		entropyGenerator.entropyComputed[height] = []byte(groupSignature)
		entropyGenerator.lastComputedEntropyHeight++

		// Don't delete this yet as need them there for gossiping to peers
		//delete(entropyGenerator.entropyShares, height)

		return true
	}
	return false
}
