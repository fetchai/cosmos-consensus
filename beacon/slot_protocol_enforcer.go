package beacon

import (
	"fmt"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
	"sync"
)

type messageEnum int

const (
	messageOK messageEnum = iota
	messageEarly
	messageInvalid
)

// The slot protocol enforcer avoids there being duplicate or phony DKG messages in the mempool/gossip.

// DKG messages are unique, and there is a finite number there should be per dkg attempt. The slot protocol enforcer
// sits in front of the mempool and blocks bad DKG messages from going in.
// It also verifies whether a block is invalid due to containing phony DKG Txs
// This means it must check whether reaped txs would invalidate a block, and remove Txs from the mempool that are
// now stale
//
// Should be attached to: dkg, the mempool, and the consensus state. If it is nill it always
// allows Txs to pass through
type SlotProtocolEnforcer struct {
	activeDKG       *DistributedKeyGeneration
	alreadySeenMsgs map[string]struct{} // Txs seen going into the mempool
	pendingTxs      []*pendingTx
	cbWhenUpdated   func([]byte, uint16, p2p.ID, *abci.Response)
	logger          log.Logger
	mtx             sync.Mutex
}

func NewSlotProtocolEnforcer() *SlotProtocolEnforcer {
	return &SlotProtocolEnforcer{
		alreadySeenMsgs: make(map[string]struct{}),
		pendingTxs:      make([]*pendingTx, 0),
		cbWhenUpdated:   nil,
		logger:          log.NewNopLogger(),
	}
}

// Function to call when there is a new dkg enabling the stored Txs to be
// verified
func (sp *SlotProtocolEnforcer) SetCbWhenUpdated(fn func([]byte, uint16, p2p.ID, *abci.Response)) {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()
	sp.cbWhenUpdated = fn
}

// Notify the enforcer that a new DKG has started. Since the enforcer is
// only notified when it starts and not finishes there is a slight inefficiency
// in that valid but stale messages could be included
// It needs to be notified on start since we do not know the validator set
func (sp *SlotProtocolEnforcer) UpdateDKG(dkg *DistributedKeyGeneration) {

	if sp == nil {
		return
	}

	sp.mtx.Lock()
	sp.activeDKG = dkg
	sp.alreadySeenMsgs = make(map[string]struct{}, 0)

	pendingTxsCopy := sp.pendingTxs
	sp.pendingTxs = make([]*pendingTx, 0)
	sp.mtx.Unlock()

	if sp.cbWhenUpdated == nil {
		sp.logger.Error(fmt.Sprintf("Cb for slot protocol enforcer is nil! dkgID: %v", dkg.dkgID))
		return
	}

	// All the txs which were potentially good we now effectively attempt to re-add
	// to the mempool. Note this needs to not have the lock since it will once again check the
	// slot protocol enforcer
	for _, pending := range pendingTxsCopy {
		sp.cbWhenUpdated(pending.tx, pending.peerID, pending.peerP2PID, pending.res)
	}

	sp.logger.Error(fmt.Sprintf("Updated with new DKG ID %v\n", dkg.dkgID))
}

// This function must be called on ALL transactions that would be added to the mempool. Normal txs
// are ok, dkg txs will be added if it is known they are ok
func (sp *SlotProtocolEnforcer) ShouldAdd(tx []byte, peerID uint16, peerP2PID p2p.ID, res *abci.Response) bool {
	sp.mtx.Lock()
	defer sp.mtx.Unlock()

	// If nil pointer always return true
	if sp == nil {
		return true
	}

	// Always allow normal txs through
	if !tx_extensions.IsDKGRelated(tx) {
		return true
	}

	// if there is a race, go ahead and add all dkg txs to the pending queue
	if sp.activeDKG == nil {
		sp.logger.Error("Adding DKG Txs to the mempool with incomplete info about dkg")
		sp.pendingTxs = append(sp.pendingTxs, &pendingTx{tx, peerID, peerP2PID, res})
		return false
	}

	status := sp.messageStatus(tx)

	switch status {
	case messageOK:
		return true

	case messageEarly:
		sp.logger.Error("Adding DKG Txs to the mempool with early info about dkg")
		sp.pendingTxs = append(sp.pendingTxs, &pendingTx{tx, peerID, peerP2PID, res})
		return false

	case messageInvalid:
		sp.logger.Error("Found invalid DKG Tx!")
		return false

	default:
		panic(fmt.Sprintf("Invalid enum received in slot protocol\n"))
		return false
	}
}

// Given a known dkg tx, is it valid for this dkg, or the next, or not at all
func (sp *SlotProtocolEnforcer) messageStatus(tx []byte) messageEnum {

	dkgMessage, err := tx_extensions.FromBytes(tx)

	if err != nil {
		sp.logger.Error("Error when recieveing dkg message to mempool", err)
	}

	// All the possible valid options for its position in the dkg slots
	messageWithinDKG := dkgMessage.DKGID == sp.activeDKG.dkgID && dkgMessage.DKGIteration == sp.activeDKG.dkgIteration
	messageNextIteration := dkgMessage.DKGID == sp.activeDKG.dkgID && dkgMessage.DKGIteration == sp.activeDKG.dkgIteration+1
	messageNextDKG := dkgMessage.DKGID == sp.activeDKG.dkgID+1 && dkgMessage.DKGIteration == 0

	if !messageWithinDKG && !messageNextIteration && !messageNextDKG {
		sp.logger.Error(fmt.Sprintf("Error when recieveing dkg message to mempool. Out of bounds: %v %v", dkgMessage.DKGID, dkgMessage.DKGIteration))
		return messageInvalid
	}

	// If the message is in the next iteration we will need to wait to verify it
	if messageNextIteration || messageNextDKG {
		return messageEarly
	}

	index, val := sp.activeDKG.validators.GetByAddress(dkgMessage.FromAddress)
	index2, _ := sp.activeDKG.validators.GetByAddress(dkgMessage.ToAddress)

	// Check whether we have seen this message combo before, regardless of whether it is valid.
	// Note, data is ignored, the signer has one attempt to put what they desire there.
	messageUniqueString := fmt.Sprintf("%v%v%v%v%v", index, index2, dkgMessage.DKGID, dkgMessage.DKGIteration, dkgMessage.Type)

	if _, exists := sp.alreadySeenMsgs[messageUniqueString]; exists {
		sp.logger.Error("already exists")
		return messageInvalid
	}

	// Otherwise, we are able to determine whether it is valid
	// using the DKG
	if status, err := sp.activeDKG.validateMessage(dkgMessage, index, val); status == types.Invalid {
		sp.logger.Error("SlotProtocolEnforcer: message staus", "from", dkgMessage.FromAddress, "err", err)
		return messageInvalid
	}

	// Since it is valid, add it to the already seen cache
	sp.alreadySeenMsgs[messageUniqueString] = struct{}{}
	return messageOK
}

// SetLogger sets the Logger.
func (sp *SlotProtocolEnforcer) SetLogger(l log.Logger) {
	sp.logger = l
}

// This is a TX which we would like to add to the mempool
// but do not yet know if it is valid since it belongs to a
// DKG which starts on the next block
type pendingTx struct {
	tx        []byte
	peerID    uint16
	peerP2PID p2p.ID
	res       *abci.Response
}
