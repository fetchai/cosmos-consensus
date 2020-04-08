package tx_extensions

import (
	"bytes"
	"fmt"
	"errors"

	amino "github.com/tendermint/go-amino"
"github.com/tendermint/tendermint/types"
)

var cdc = amino.NewCodec()
type DKGMessage types.DKGMessage

func init() {
	RegisterMessages(cdc)
	types.RegisterBlockAmino(cdc)
}

func RegisterMessages(cdc *amino.Codec) {
	cdc.RegisterConcrete(&DKGMessage{}, "tendermint/DKGMessage", nil)
}

// Return the DKG message as bytes
func AsBytes(msg *DKGMessage) (ret []byte) {

	as_bytes := cdc.MustMarshalBinaryBare(*msg)
	ret = append([]byte("SP:DKG"), as_bytes...)

	return
}

func FromBytes(msg []byte) (ret *DKGMessage, err error) {

	ret = &DKGMessage{}
	err = cdc.UnmarshalBinaryBare(msg[6:], ret)
	return
}

// Handler for converting DKG message from a string
func AsDKG(msg interface{}) (ret DKGMessage, err error) {

	switch v := msg.(type) {
	case string:
		ret.Data = []byte(v)
	default:
		err = errors.New("Failed to convert DKG message")
	}
	return
}

// IsDKGRelated informs as to whether this TX (bytes) is an on chain DKG transaction.
// At the moment this is signified by the leading bytes being 'SP:DKG' (special tx: DKG)
func IsDKGRelated(tx []byte) bool {
	if len(tx) >= 6 && bytes.Equal(tx[0:6], []byte("SP:DKG")) {
		return true
	}
	return false
}

// The struct designed to handle sending and receiving messages via the chain
type SpecialTxHandler struct {
	// Trigger this when new DKG messages are seen by the chain
	cb_confirmed_message func(DKGMessage)

	// Trigger this to send DKG TX to the mempool
	cb_submit_special_tx func([]byte)
}

// Submit a special TX to the chain
func (txHandler *SpecialTxHandler) SubmitSpecialTx(message interface{}) {
	switch v := message.(type) {
	case DKGMessage:
		to_send := AsBytes(&v)
		if txHandler.cb_submit_special_tx != nil {
			txHandler.cb_submit_special_tx(to_send)
		}
	default:
		if as_dkg_msg, error := AsDKG(message); error == nil {
			txHandler.cb_submit_special_tx(AsBytes(&as_dkg_msg))
		} else {
			fmt.Printf("Unknown type %T attempted to submit to the chain!\n", v)
		}
	}
}

// Set the closure to be triggered when submitting a Tx to the mempool
func (txHandler *SpecialTxHandler) ToSubmitTx(cb func([]byte)) {
	txHandler.cb_submit_special_tx = cb
}

// Set the closure to be triggered when special Txs are seen on the chain
func (txHandler *SpecialTxHandler) WhenChainTxSeen(cb func(DKGMessage)) {
	txHandler.cb_confirmed_message = cb
}

// Call this when new special Txs are seen on the chain
func (txHandler *SpecialTxHandler) SpecialTxSeen(tx []byte) {
	fmt.Printf("Recieved DKG TX in the chain \n")
	resp, err := FromBytes(tx)
	if err == nil {
		fmt.Printf("Note: data is: %v\n", string(resp.Data))
		if txHandler.cb_confirmed_message != nil {
			txHandler.cb_confirmed_message(*resp)
		}
	} else {
		fmt.Printf("Failed to decode DKG tx!\n")
	}
}
