package coregrpc_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/abci/example/kvstore"
	core_grpc "github.com/tendermint/tendermint/rpc/grpc"
	rpctest "github.com/tendermint/tendermint/rpc/test"
)

func TestMain(m *testing.M) {
	// start a tendermint node in the background to test against
	app := kvstore.NewApplication()
	node := rpctest.StartTendermint(app)

	code := m.Run()

	// and shut down proper at the end
	rpctest.StopTendermint(node)
	os.Exit(code)
}

func TestBroadcastTxCommit(t *testing.T) {
	res, err := rpctest.GetGRPCClient().BroadcastTxCommit(
		context.Background(),
		&core_grpc.RequestBroadcastTx{Tx: []byte("this is a tx")},
	)
	require.NoError(t, err)
	require.EqualValues(t, 0, res.CheckTx.Code)
	require.EqualValues(t, 0, res.DeliverTx.Code)
}

func TestBroadcastTxSync(t *testing.T) {
	res, err := rpctest.GetGRPCClient().BroadcastTxSync(
		context.Background(),
		&core_grpc.RequestBroadcastTx{Tx: []byte("this is a tx 2")},
	)
	require.NoError(t, err)
	require.EqualValues(t, 0, res.CheckTx.Code)
}

func TestSubscribe(t *testing.T) {
	client := rpctest.GetGRPCClient()
	_, err := client.Subscribe(
		context.Background(),
		&core_grpc.RequestSubscribe{Query: "tm.event='NewBlock'"},
	)
	require.NoError(t, err)

	_, err = client.BroadcastTxSync(
		context.Background(),
		&core_grpc.RequestBroadcastTx{Tx: []byte("this is a tx 3")},
	)
	require.NoError(t, err)

	_, err = client.Unubscribe(
		context.Background(),
		&core_grpc.RequestUnsubscribe{Query: "tm.event='NewBlock'"},
	)
	require.NoError(t, err)
}
