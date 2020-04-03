package tx_extensions

import (
	"bytes"
	"fmt"
)

// Core DKG message
type DKGMessage struct {
	Message string
}

// Return the DKG message as bytes
func AsBytes(msg *DKGMessage) (ret []byte) {
	return append([]byte("DKGTX"), []byte(msg.Message)...)
}

// IsDKGRelated informs as to whether this TX (bytes) is an on chain DKG transaction.
// At the moment this is signified by the leading bytes being 'DKGTX'
func IsDKGRelated(tx []byte) bool {
	if len(tx) >= 5 && bytes.Equal(tx[0:5], []byte("DKGTX")) {
		return true
	}
	return false
}

// The struct designed to handle sending and receiving messages via the chain
type SpecialTxHandler struct {
	// Trigger this when new DKG messages are seen by the chain
	cb_confirmed_message func(DKGMessage)

	// Trigger this to send DKGTX to the mempool
	cb_submit_special_tx func([]byte)
}

// Submit a special TX to the chain
func (txHandler *SpecialTxHandler) SubmitSpecialTx(message interface{}) {
	switch v := message.(type) {
	case DKGMessage:
		to_send := AsBytes(&v)
		txHandler.cb_submit_special_tx(to_send)
	default:
		fmt.Printf("Unknown type %T attempted to submit to the chain!\n", v)
	}
}

// Set the closure to be triggered when submitting a Tx to the mempool
func (txHandler *SpecialTxHandler) ToSubmitTx(cb func([]byte)) {
	txHandler.cb_submit_special_tx = cb
}

// Call this when new special Txs are seen on the chain
func (txHandler *SpecialTxHandler) SpecialTxSeen(tx []byte) {
	fmt.Printf("Recieved DKG TX in the chain \n")
	if txHandler.cb_confirmed_message != nil {
		txHandler.cb_confirmed_message(DKGMessage{string(tx)})
	}
}
