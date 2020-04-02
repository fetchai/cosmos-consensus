package beacon

import (
	amino "github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterMessages(cdc)
	RegisterDKGMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
