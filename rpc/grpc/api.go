package coregrpc

import (
	"context"
	fmt "fmt"

	abci "github.com/tendermint/tendermint/abci/types"
	core "github.com/tendermint/tendermint/rpc/core"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	rpctypes "github.com/tendermint/tendermint/rpc/lib/types"
	types "github.com/tendermint/tendermint/types"
	"google.golang.org/grpc/peer"
)

type grpcAPI struct {
}

func (bapi *grpcAPI) Ping(ctx context.Context, req *RequestPing) (*ResponsePing, error) {
	// kvstore so we can check if the server is up
	return &ResponsePing{}, nil
}

func (bapi *grpcAPI) BroadcastTxCommit(ctx context.Context, req *RequestBroadcastTx) (*ResponseBroadcastTxCommit, error) {
	// NOTE: there's no way to get client's remote address
	// see https://stackoverflow.com/questions/33684570/session-and-remote-ip-address-in-grpc-go
	res, err := core.BroadcastTxCommit(&rpctypes.Context{}, req.Tx)
	if err != nil {
		return nil, err
	}

	return &ResponseBroadcastTxCommit{
		Hash: res.Hash,
		CheckTx: &abci.ResponseCheckTx{
			Code: res.CheckTx.Code,
			Data: res.CheckTx.Data,
			Log:  res.CheckTx.Log,
		},
		DeliverTx: &abci.ResponseDeliverTx{
			Code: res.DeliverTx.Code,
			Data: res.DeliverTx.Data,
			Log:  res.DeliverTx.Log,
		},
	}, nil
}

func (bapi *grpcAPI) BroadcastTxSync(ctx context.Context, req *RequestBroadcastTx) (*ResponseBroadcastTxSync, error) {
	res, err := core.BroadcastTxSync(&rpctypes.Context{}, req.Tx)
	if err != nil {
		return nil, err
	}

	return &ResponseBroadcastTxSync{
		Hash: res.Hash,
		CheckTx: &abci.ResponseCheckTx{
			Code: res.Code,
			Data: res.Data,
			Log:  res.Log,
		},
	}, nil
}

func (bapi *grpcAPI) BroadcastTxAsync(ctx context.Context, req *RequestBroadcastTx) (*ResponseBroadcastTxAsync, error) {
	res, err := core.BroadcastTxAsync(&rpctypes.Context{}, req.Tx)
	if err != nil {
		return nil, err
	}

	return &ResponseBroadcastTxAsync{
		Hash: res.Hash,
	}, nil
}

func responseTxConvert(res *ctypes.ResultTx) *ResponseTx {
	return &ResponseTx{
		Hash:     res.Hash,
		Height:   res.Height,
		Index:    res.Index,
		TxResult: &res.TxResult,
		Tx:       res.Tx,
	}
}

func (bapi *grpcAPI) Tx(ctx context.Context, req *RequestTx) (*ResponseTx, error) {
	res, err := core.Tx(&rpctypes.Context{}, req.Hash, req.Prove)
	if err != nil {
		return nil, err
	}

	return responseTxConvert(res), nil
}

func (bapi *grpcAPI) TxSearch(ctx context.Context, req *RequestTxSearch) (*ResponseTxSearch, error) {
	res, err := core.TxSearch(&rpctypes.Context{}, req.Query, req.Prove, int(req.Page), int(req.PerPage), req.OrderBy)
	if err != nil {
		return nil, err
	}

	list := make([]*ResponseTx, res.TotalCount)

	for i := 0; i < res.TotalCount; i++ {
		list[i] = responseTxConvert(res.Txs[i])
	}

	return &ResponseTxSearch{
		Txs: list,
	}, nil
}

func getAddress(ctx *context.Context) (string, error) {
	peer, ok := peer.FromContext(*ctx)
	if !ok {
		return "", fmt.Errorf("address not found")
	}
	return peer.Addr.String(), nil
}

func (bapi *grpcAPI) Subscribe(query *RequestSubscribe, stream GrpcAPI_SubscribeServer) error {
	ctx := stream.Context()
	addr, err := getAddress(&ctx)
	if err != nil {
		return err
	}
	msgChan, errChan, err := core.GRPCSubscribe(&ctx, addr, query.Query)
	if err != nil {
		return err
	}
	for {
		select {
		case msg := <-msgChan:
			response := ResponseSubscribe{Query: msg.Query}
			for key, values := range msg.Events {
				v := EventItem{}
				v.Event = values
				response.Events[key] = &v
			}
			switch msgTyped := (msg.Data).(type) {
			case types.EventDataNewBlockHeader:
				response.Type = "new_block_header"
				r, err := newBlockHeaderEventToProto(&msgTyped)
				if err != nil {
					logger.Error(err.Error())
					continue
				}
				response.NewBlockHeader = r
			case types.EventDataNewBlock:
				response.Type = "new_block"
				r, err := newBlockEventToProto(&msgTyped)
				if err != nil {
					logger.Error(err.Error())
					continue
				}
				response.NewBlock = r
			default:
				err := fmt.Errorf("data type not supported %T", msg)
				logger.Error(err.Error())
				return err
			}
		case err := <-errChan:
			return err
		}
	}
	return nil
}

func (bapi *grpcAPI) Unubscribe(ctx context.Context, req *RequestUnsubscribe) (*ResponseUnsubscribe, error) {
	addr, err := getAddress(&ctx)
	if err != nil {
		return nil, err
	}
	_, err = core.GRPCUnsubscribe(&ctx, addr, req.Query)
	if err != nil {
		return nil, err
	}
	return &ResponseUnsubscribe{}, nil
}

func (bapi *grpcAPI) UnubscribeAll(ctx context.Context, req *RequestUnsubscribe) (*ResponseUnsubscribe, error) {
	addr, err := getAddress(&ctx)
	if err != nil {
		return nil, err
	}
	_, err = core.GRPCUnsubscribeAll(addr)
	if err != nil {
		return nil, err
	}
	return &ResponseUnsubscribe{}, nil
}
