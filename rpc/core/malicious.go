package core

import (
	"github.com/tendermint/tendermint/malicious"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	rpctypes "github.com/tendermint/tendermint/rpc/lib/types"
)

// MutateDKGMessage adds mutation to the dkg message mutations and returns nothing
func MutateDKGMessage(ctx *rpctypes.Context, mutation malicious.DKGMessageMutation) (
	*ctypes.ResultMutateDKGMessage, error) {
	logger.Debug("MutateDKGMessage", "mutation", mutation)
	messageMutator.SetDKGMessageMutation(mutation)
	return &ctypes.ResultMutateDKGMessage{}, nil
}
