package core

import (
	"github.com/tendermint/tendermint/malicious"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	rpctypes "github.com/tendermint/tendermint/rpc/lib/types"
)

// MutateDKGMessage adds mutation to the dkg message mutations and returns nothing
func MutateDKGMessage(ctx *rpctypes.Context, mutation malicious.DKGMessageMutation, on bool) (
	*ctypes.ResultMutateDKGMessage, error) {
	messageMutator.SetDKGMessageMutation(mutation, on)
	return &ctypes.ResultMutateDKGMessage{}, nil
}
