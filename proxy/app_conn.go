package proxy

import (
	"fmt"
	"github.com/tendermint/tendermint/libs/kv"
	abcicli "github.com/tendermint/tendermint/abci/client"
	"github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/tx_extensions"
)

//----------------------------------------------------------------------------------------
// Enforce which abci msgs can be sent on a connection at the type level

type AppConnConsensus interface {
	SetResponseCallback(abcicli.Callback)
	Error() error

	InitChainSync(types.RequestInitChain) (*types.ResponseInitChain, error)

	BeginBlockSync(types.RequestBeginBlock) (*types.ResponseBeginBlock, error)
	DeliverTxAsync(types.RequestDeliverTx) *abcicli.ReqRes
	EndBlockSync(types.RequestEndBlock) (*types.ResponseEndBlock, error)
	CommitSync() (*types.ResponseCommit, error)
}

type AppConnMempool interface {
	SetResponseCallback(abcicli.Callback)
	Error() error

	CheckTxAsync(types.RequestCheckTx) *abcicli.ReqRes

	FlushAsync() *abcicli.ReqRes
	FlushSync() error
}

type AppConnQuery interface {
	Error() error

	EchoSync(string) (*types.ResponseEcho, error)
	InfoSync(types.RequestInfo) (*types.ResponseInfo, error)
	QuerySync(types.RequestQuery) (*types.ResponseQuery, error)

	//	SetOptionSync(key string, value string) (res types.Result)
}

//-----------------------------------------------------------------------------------------
// Implements AppConnConsensus (subset of abcicli.Client)

type appConnConsensus struct {
	appConn abcicli.Client
	specialTxHandler *tx_extensions.SpecialTxHandler
}

func NewAppConnConsensus(appConn abcicli.Client, handler *tx_extensions.SpecialTxHandler) *appConnConsensus {
	return &appConnConsensus{
		appConn: appConn,
		specialTxHandler: handler,
	}
}

func (app *appConnConsensus) SetResponseCallback(cb abcicli.Callback) {
	app.appConn.SetResponseCallback(cb)
}

func (app *appConnConsensus) Error() error {
	return app.appConn.Error()
}

func (app *appConnConsensus) InitChainSync(req types.RequestInitChain) (*types.ResponseInitChain, error) {
	return app.appConn.InitChainSync(req)
}

func (app *appConnConsensus) BeginBlockSync(req types.RequestBeginBlock) (*types.ResponseBeginBlock, error) {
	return app.appConn.BeginBlockSync(req)
}

func (app *appConnConsensus) DeliverTxAsync(req types.RequestDeliverTx) *abcicli.ReqRes {

	// Special case for DKG TXs
	if tx_extensions.IsDKGRelated(req.Tx) {

		no_events := []types.Event{
			{
				Type: "app",
				Attributes: []kv.Pair{
					{Key: []byte("creator"), Value: []byte("Cosmoshi Netowoko")},
					{Key: []byte("key"), Value: req.Tx},
				},
			},
		}

		// If the TX is a DKG tx make a 'fake' abci call to pretend the TX was delivered
		fakeRes := types.ResponseDeliverTx{Code: types.CodeTypeOK, Events: no_events}

		reqRes := abcicli.NewReqRes(types.ToRequestDeliverTx(req))
		reqRes.Response = types.ToResponseDeliverTx(fakeRes)
		reqRes.SetDone()

		app.appConn.TriggerResponseCallback(types.ToRequestDeliverTx(req), reqRes.Response)
		if app.specialTxHandler != nil {
			app.specialTxHandler.ConfirmedMessage(req.Tx)
		} else {
			fmt.Printf("should not happen \n")
		}

		return reqRes
	}

	return app.appConn.DeliverTxAsync(req)
}

func (app *appConnConsensus) EndBlockSync(req types.RequestEndBlock) (*types.ResponseEndBlock, error) {
	return app.appConn.EndBlockSync(req)
}

func (app *appConnConsensus) CommitSync() (*types.ResponseCommit, error) {
	return app.appConn.CommitSync()
}

//------------------------------------------------
// Implements AppConnMempool (subset of abcicli.Client)

type appConnMempool struct {
	appConn abcicli.Client
}

func NewAppConnMempool(appConn abcicli.Client) *appConnMempool {
	return &appConnMempool{
		appConn: appConn,
	}
}

func (app *appConnMempool) SetResponseCallback(cb abcicli.Callback) {
	app.appConn.SetResponseCallback(cb)
}

func (app *appConnMempool) Error() error {
	return app.appConn.Error()
}

func (app *appConnMempool) FlushAsync() *abcicli.ReqRes {
	return app.appConn.FlushAsync()
}

func (app *appConnMempool) FlushSync() error {
	return app.appConn.FlushSync()
}

func (app *appConnMempool) CheckTxAsync(req types.RequestCheckTx) *abcicli.ReqRes {

	// Special case for DKG TXs
	if tx_extensions.IsDKGRelated(req.Tx) {
		// If the TX is a DKG tx make a 'fake' abci call to determine the TX is ok.
		fakeRes := types.ResponseCheckTx{Code: types.CodeTypeOK, GasWanted: 1}

		reqRes := abcicli.NewReqRes(types.ToRequestCheckTx(req))
		reqRes.Response = types.ToResponseCheckTx(fakeRes)
		reqRes.SetDone()

		return reqRes
	}

	return app.appConn.CheckTxAsync(req)
}

//------------------------------------------------
// Implements AppConnQuery (subset of abcicli.Client)

type appConnQuery struct {
	appConn abcicli.Client
}

func NewAppConnQuery(appConn abcicli.Client) *appConnQuery {
	return &appConnQuery{
		appConn: appConn,
	}
}

func (app *appConnQuery) Error() error {
	return app.appConn.Error()
}

func (app *appConnQuery) EchoSync(msg string) (*types.ResponseEcho, error) {
	return app.appConn.EchoSync(msg)
}

func (app *appConnQuery) InfoSync(req types.RequestInfo) (*types.ResponseInfo, error) {
	return app.appConn.InfoSync(req)
}

func (app *appConnQuery) QuerySync(reqQuery types.RequestQuery) (*types.ResponseQuery, error) {
	return app.appConn.QuerySync(reqQuery)
}
