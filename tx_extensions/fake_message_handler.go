package tx_extensions

import (
	//"bytes"
	"fmt"
	"sync"
	//"errors"

	//amino "github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/types"
)

// Fake representation of the chain, for testing.
// Allows messages to be submitted by different parties (thread safe)
// and dispatches these messages to everyone 
type FakeMessageHandler struct {
	mtx sync.RWMutex
	cb_confirmed_message []func(int64, []*types.DKGMessage)
	cb_submit_special_tx func([]byte)

	currentlyPending []*types.DKGMessage
}

var _ MessageHandler = &FakeMessageHandler{}

func NewFakeMessageHandler() (ret *FakeMessageHandler) {

	ret = &FakeMessageHandler{}
	// Default such that TXs are submitted to the pending pool
	// (rather than the chain)
	ret.ToSubmitTx(func(tx []byte) { ret.SpecialTxSeen(tx)  })
	return
}

// Submit a special TX to the chain (converts to bytes)
func (txHandler *FakeMessageHandler) SubmitSpecialTx(message interface{}) {
	switch v := message.(type) {
	case types.DKGMessage:
		to_send := AsBytes(&v)
		txHandler.SpecialTxSeen(to_send)
	case *types.DKGMessage:
		to_send := AsBytes(v)
		txHandler.SpecialTxSeen(to_send)
	default:
		fmt.Printf("Unknown type %T attempted to submit to the chain (fake message handler)!\n", v)
	}
}

func (txHandler *FakeMessageHandler) SubmitTx(tx types.DKGMessage) {
	txHandler.mtx.Lock()
	defer txHandler.mtx.Unlock()
	
	txHandler.currentlyPending = append(txHandler.currentlyPending, &tx)
}

// Set the closure to be triggered when submitting a Tx to the mempool
// Not normally needed externally since set when getting new fake message handler
func (txHandler *FakeMessageHandler) ToSubmitTx(cb func([]byte)) {
	txHandler.cb_submit_special_tx = cb
}

func (txHandler *FakeMessageHandler) EndBlock(blockHeight int64) {
	txHandler.mtx.Lock()
	currentlyPending := txHandler.currentlyPending
	txHandler.mtx.Unlock()

	// Call without the lock to avoid deadlock if toExecute can somehow submit
	// TXs to this struct
	for _, toExecute := range txHandler.cb_confirmed_message {
		toExecute(blockHeight, currentlyPending)
	}

	txHandler.currentlyPending = make([]*types.DKGMessage, 0)
}

// Set the closure to be triggered when special Txs are seen on the chain
func (txHandler *FakeMessageHandler) WhenChainTxSeen(cb func(int64, []*types.DKGMessage)) {
	txHandler.cb_confirmed_message = append(txHandler.cb_confirmed_message, cb)
}

// Call this when new special Txs are seen on the chain
func (txHandler *FakeMessageHandler) SpecialTxSeen(tx []byte) {
	resp, err := FromBytes(tx)
	if err == nil {
		txHandler.SubmitTx(*resp)
	} else {
		fmt.Printf("Failed to decode DKG tx!\n")
	}
}
