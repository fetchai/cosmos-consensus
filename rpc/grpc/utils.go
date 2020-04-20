package coregrpc

import (
	"encoding/json"

	abci "github.com/tendermint/tendermint/abci/types"
	types "github.com/tendermint/tendermint/types"
)

func blockHeaderToProto(header *types.Header) (res *abci.Header, err error) {
	res = nil
	encoded, err := json.Marshal(header)
	if err != nil {
		return
	}
	res = &abci.Header{}
	err = json.Unmarshal(encoded, *res)
	return
}

func newBlockHeaderEventToProto(msg *types.EventDataNewBlockHeader) (res *EventNewBlockHeader, err error) {
	header, err := blockHeaderToProto(&msg.Header)
	if err != nil {
		return
	}
	res = &EventNewBlockHeader{}
	res.Header = header
	res.NumTxs = msg.NumTxs
	res.ResultBeginBlock = &msg.ResultBeginBlock
	res.ResultEndBlock = &msg.ResultEndBlock
	return
}

func newBlockEventToProto(msg *types.EventDataNewBlock) (res *EventNewBlock, err error) {
	header, err := blockHeaderToProto(&msg.Block.Header)
	if err != nil {
		return
	}
	res = &EventNewBlock{}
	res.Block.Header = header
	res.Block.Data.Data = make([][]byte, len(msg.Block.Data.Txs))
	for i, v := range msg.Block.Data.Txs {
		res.Block.Data.Data[i] = v
	}
	res.Block.Data.Hash = msg.Block.Data.Hash()
	//todo evidence, commit
	res.ResultBeginBlock = &msg.ResultBeginBlock
	res.ResultEndBlock = &msg.ResultEndBlock
	return
}
