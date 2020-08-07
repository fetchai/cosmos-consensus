package mempool

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"fmt"
	"github.com/pkg/errors"
	"sync"
	"sync/atomic"
	"time"

	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	auto "github.com/tendermint/tendermint/libs/autofile"
	"github.com/tendermint/tendermint/libs/clist"
	"github.com/tendermint/tendermint/libs/log"
	tmmath "github.com/tendermint/tendermint/libs/math"
	tmos "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/proxy"
	"github.com/tendermint/tendermint/tx_extensions"
	"github.com/tendermint/tendermint/types"
)

//--------------------------------------------------------------------------------

// CListMempool is an ordered in-memory pool for transactions before they are
// proposed in a consensus round. Transaction validity is checked using the
// CheckTx abci message before the transaction is added to the pool. The
// mempool uses a concurrent list structure for storing transactions that can
// be efficiently accessed by multiple concurrent readers.
// Transactions are pushed onto the back of the queue, unless they are a priority
// in which case they go to the front. Tx reaping (for block production) is
// done from the front, while the readers (tx gossip) go from front to back
type CListMempool struct {
	// Atomic integers
	height     int64 // the last block Update()'d to
	txsBytes   int64 // total size of mempool, in bytes
	rechecking int32 // for re-checking filtered txs on Update()

	// notify listeners (ie. consensus) when txs are available
	notifiedTxsAvailable bool
	txsAvailable         chan struct{} // fires once for each height, when the mempool is not empty

	config *cfg.MempoolConfig

	proxyMtx     sync.Mutex
	proxyAppConn proxy.AppConnMempool
	txs          *clist.CList // concurrent linked-list of good txs
	preCheck     PreCheckFunc
	postCheck    PostCheckFunc

	// Map of peerID to location in the linked list they have broadcast to
	peerPointers map[uint16]peerPointer

	// Track whether we're rechecking txs.
	// These are not protected by a mutex and are expected to be mutated
	// in serial (ie. by abci responses which are called in serial).
	recheckCursor *clist.CElement // next expected response
	recheckEnd    *clist.CElement // re-checking stops here

	// Map for quick access to txs to record sender in CheckTx.
	// txsMap: txKey -> CElement
	txsMap sync.Map

	// Keep a cache of already-seen txs.
	// This reduces the pressure on the proxyApp.
	cache txCache

	// A log of mempool txs
	wal *auto.AutoFile

	// enforce DKG Txs being unique - this is a func to
	// avoid a circular dependency on beacon. Returns true
	// if it is ok
	slotProtocolEnforcer func([]byte, uint16, p2p.ID, *abci.Response) bool

	logger log.Logger
	metrics *Metrics
}

// The peerPointer keeps a reference to the location in the mempool (list) that
// the peer has gossiped so far. Priority transactions which have been inserted
// into the front of the list (rather than the back), are likely to have been
// missed (already past that point) and so are stored here to guarantee
// they are sent, and are sent before any other Txs
type peerPointer struct {
	Element *clist.CElement       // The element last gossiped to the peer
	PriorityTxs []*clist.CElement // Any Txs which are a high priority to gossip
}

var _ Mempool = &CListMempool{}

// CListMempoolOption sets an optional parameter on the mempool.
type CListMempoolOption func(*CListMempool)

// NewCListMempool returns a new mempool with the given configuration and connection to an application.
func NewCListMempool(
	config *cfg.MempoolConfig,
	proxyAppConn proxy.AppConnMempool,
	height int64,
	slotProtocolEnforcer func([]byte, uint16, p2p.ID, *abci.Response) bool,
	options ...CListMempoolOption,
) *CListMempool {
	mempool := &CListMempool{
		config:               config,
		proxyAppConn:         proxyAppConn,
		txs:                  clist.New(),
		peerPointers:         make(map[uint16]peerPointer),
		height:               height,
		rechecking:           0,
		recheckCursor:        nil,
		recheckEnd:           nil,
		logger:               log.NewNopLogger(),
		metrics:              NopMetrics(),
		slotProtocolEnforcer: slotProtocolEnforcer,
	}
	if config.CacheSize > 0 {
		mempool.cache = newMapTxCache(config.CacheSize)
	} else {
		mempool.cache = nopTxCache{}
	}
	proxyAppConn.SetResponseCallback(mempool.globalCb)
	for _, option := range options {
		option(mempool)
	}

	return mempool
}

// NOTE: not thread safe - should only be called once, on startup
func (mem *CListMempool) EnableTxsAvailable() {
	mem.txsAvailable = make(chan struct{}, 1)
}

func (mem *CListMempool) GetHeight() int64 {
	return mem.height
}

// SetLogger sets the Logger.
func (mem *CListMempool) SetLogger(l log.Logger) {
	mem.logger = l
}

// WithPreCheck sets a filter for the mempool to reject a tx if f(tx) returns
// false. This is ran before CheckTx.
func WithPreCheck(f PreCheckFunc) CListMempoolOption {
	return func(mem *CListMempool) { mem.preCheck = f }
}

// WithPostCheck sets a filter for the mempool to reject a tx if f(tx) returns
// false. This is ran after CheckTx.
func WithPostCheck(f PostCheckFunc) CListMempoolOption {
	return func(mem *CListMempool) { mem.postCheck = f }
}

// WithMetrics sets the metrics.
func WithMetrics(metrics *Metrics) CListMempoolOption {
	return func(mem *CListMempool) { mem.metrics = metrics }
}

// *panics* if can't create directory or open file.
// *not thread safe*
func (mem *CListMempool) InitWAL() {
	walDir := mem.config.WalDir()
	err := tmos.EnsureDir(walDir, 0700)
	if err != nil {
		panic(errors.Wrap(err, "Error ensuring WAL dir"))
	}
	af, err := auto.OpenAutoFile(walDir + "/wal")
	if err != nil {
		panic(errors.Wrap(err, "Error opening WAL file"))
	}
	mem.wal = af
}

func (mem *CListMempool) CloseWAL() {
	mem.proxyMtx.Lock()
	defer mem.proxyMtx.Unlock()

	if err := mem.wal.Close(); err != nil {
		mem.logger.Error("Error closing WAL", "err", err)
	}
	mem.wal = nil
}

func (mem *CListMempool) Lock() {
	mem.proxyMtx.Lock()
}

func (mem *CListMempool) Unlock() {
	mem.proxyMtx.Unlock()
}

func (mem *CListMempool) Size() int {
	return mem.txs.Len()
}

func (mem *CListMempool) TxsBytes() int64 {
	return atomic.LoadInt64(&mem.txsBytes)
}

func (mem *CListMempool) FlushAppConn() error {
	return mem.proxyAppConn.FlushSync()
}

func (mem *CListMempool) Flush() {
	mem.proxyMtx.Lock()
	defer mem.proxyMtx.Unlock()

	mem.cache.Reset()

	for e := mem.txs.Front(); e != nil; e = e.Next() {
		mem.txs.Remove(e)
		e.DetachPrev()
	}

	mem.txsMap = sync.Map{}
	_ = atomic.SwapInt64(&mem.txsBytes, 0)
}

// TxsWaitChan returns a channel to wait on transactions. It will be closed
// once the mempool is not empty (ie. the internal `mem.txs` has at least one
// element)
func (mem *CListMempool) TxsWaitChan() <-chan struct{} {
	return mem.txs.WaitChan()
}

// It blocks if we're waiting on Update() or Reap().
// cb: A callback from the CheckTx command.
//     It gets called from another goroutine.
// CONTRACT: Either cb will get called, or err returned.
func (mem *CListMempool) CheckTx(tx types.Tx, cb func(*abci.Response), txInfo TxInfo) (err error) {
	mem.proxyMtx.Lock()
	// use defer to unlock mutex because application (*local client*) might panic
	defer mem.proxyMtx.Unlock()

	var (
		memSize  = mem.Size()
		txsBytes = mem.TxsBytes()
		txSize   = len(tx)
	)
	if memSize >= mem.config.Size ||
		int64(txSize)+txsBytes > mem.config.MaxTxsBytes {
		return ErrMempoolIsFull{
			memSize, mem.config.Size,
			txsBytes, mem.config.MaxTxsBytes}
	}

	// The size of the corresponding amino-encoded TxMessage
	// can't be larger than the maxMsgSize, otherwise we can't
	// relay it to peers.
	if txSize > mem.config.MaxTxBytes {
		return ErrTxTooLarge{mem.config.MaxTxBytes, txSize}
	}

	if mem.preCheck != nil {
		if err := mem.preCheck(tx); err != nil {
			return ErrPreCheck{err}
		}
	}

	// CACHE
	if !mem.cache.Push(tx) {
		// Record a new sender for a tx we've already seen.
		// Note it's possible a tx is still in the cache but no longer in the mempool
		// (eg. after committing a block, txs are removed from mempool but not cache),
		// so we only record the sender for txs still in the mempool.
		if e, ok := mem.txsMap.Load(txKey(tx)); ok {
			memTx := e.(*clist.CElement).Value.(*mempoolTx)
			memTx.senders.LoadOrStore(txInfo.SenderID, true)
			// TODO: consider punishing peer for dups,
			// its non-trivial since invalid txs can become valid,
			// but they can spam the same tx with little cost to them atm.
		}

		return ErrTxInCache
	}
	// END CACHE

	// WAL
	if mem.wal != nil {
		// TODO: Notify administrators when WAL fails
		_, err := mem.wal.Write([]byte(tx))
		if err != nil {
			mem.logger.Error("Error writing to WAL", "err", err)
		}
		_, err = mem.wal.Write([]byte("\n"))
		if err != nil {
			mem.logger.Error("Error writing to WAL", "err", err)
		}
	}
	// END WAL

	// NOTE: proxyAppConn may error if tx buffer is full
	if err = mem.proxyAppConn.Error(); err != nil {
		return err
	}

	reqRes := mem.proxyAppConn.CheckTxAsync(abci.RequestCheckTx{Tx: tx})
	reqRes.SetCallback(mem.reqResCb(tx, txInfo.SenderID, txInfo.SenderP2PID, cb))

	return nil
}

// Global callback that will be called after every ABCI response.
// Having a single global callback avoids needing to set a callback for each request.
// However, processing the checkTx response requires the peerID (so we can track which txs we heard from who),
// and peerID is not included in the ABCI request, so we have to set request-specific callbacks that
// include this information. If we're not in the midst of a recheck, this function will just return,
// so the request specific callback can do the work.
// When rechecking, we don't need the peerID, so the recheck callback happens here.
func (mem *CListMempool) globalCb(req *abci.Request, res *abci.Response) {
	if mem.recheckCursor == nil {
		return
	}

	mem.metrics.RecheckTimes.Add(1)
	mem.resCbRecheck(req, res)

	// update metrics
	mem.metrics.Size.Set(float64(mem.Size()))
	mem.metrics.SizeBytes.Set(float64(mem.TxsBytes()))
}

// Request specific callback that should be set on individual reqRes objects
// to incorporate local information when processing the response.
// This allows us to track the peer that sent us this tx, so we can avoid sending it back to them.
// NOTE: alternatively, we could include this information in the ABCI request itself.
//
// External callers of CheckTx, like the RPC, can also pass an externalCb through here that is called
// when all other response processing is complete.
//
// Used in CheckTx to record PeerID who sent us the tx.
func (mem *CListMempool) reqResCb(
	tx []byte,
	peerID uint16,
	peerP2PID p2p.ID,
	externalCb func(*abci.Response),
) func(res *abci.Response) {
	return func(res *abci.Response) {
		if mem.recheckCursor != nil {
			// this should never happen
			panic("recheck cursor is not nil in reqResCb")
		}

		mem.ResCbFirstTime(tx, peerID, peerP2PID, res)

		// update metrics
		mem.metrics.Size.Set(float64(mem.Size()))
		mem.metrics.SizeBytes.Set(float64(mem.TxsBytes()))

		// passed in by the caller of CheckTx, eg. the RPC
		if externalCb != nil {
			externalCb(res)
		}
	}
}

func isPriority(tx types.Tx) bool {
	return tx_extensions.IsDKGRelated(tx)
}

// Called from:
//  - ResCbFirstTime (lock not held) if tx is valid
func (mem *CListMempool) addTx(memTx *mempoolTx) {
	if isPriority(memTx.tx) {
		e := mem.txs.PushFront(memTx)
		mem.txsMap.Store(txKey(memTx.tx), e)
	} else {
		e := mem.txs.PushBack(memTx)
		mem.txsMap.Store(txKey(memTx.tx), e)
	}
	atomic.AddInt64(&mem.txsBytes, int64(len(memTx.tx)))
	mem.metrics.TxSizeBytes.Observe(float64(len(memTx.tx)))
}

// Called from:
//  - Update (lock held) if tx was committed
// 	- resCbRecheck (lock not held) if tx was invalidated
func (mem *CListMempool) removeTx(tx types.Tx, elem *clist.CElement, removeFromCache bool) {
	mem.txs.Remove(elem)
	elem.DetachPrev()
	mem.txsMap.Delete(txKey(tx))
	atomic.AddInt64(&mem.txsBytes, int64(-len(tx)))

	if removeFromCache {
		mem.cache.Remove(tx)
	}
}

// callback, which is called after the app checked the tx for the first time.
//
// The case where the app checks the tx for the second and subsequent times is
// handled by the resCbRecheck callback.
func (mem *CListMempool) ResCbFirstTime(
	tx []byte,
	peerID uint16,
	peerP2PID p2p.ID,
	res *abci.Response,
) {

	// Check if this Tx passes the slot protocol enforcer. If it is ambiguous, the
	// enforcer will later call ResCbFirstTime with the same arguments when it knows
	if mem.slotProtocolEnforcer != nil && !mem.slotProtocolEnforcer(tx, peerID, peerP2PID, res) {
		return
	}

	switch r := res.Value.(type) {
	case *abci.Response_CheckTx:
		var postCheckErr error
		if mem.postCheck != nil {
			postCheckErr = mem.postCheck(tx, r.CheckTx)
		}
		if (r.CheckTx.Code == abci.CodeTypeOK) && postCheckErr == nil {
			memTx := &mempoolTx{
				height:    mem.height,
				gasWanted: r.CheckTx.GasWanted,
				tx:        tx,
			}
			memTx.senders.Store(peerID, true)
			mem.addTx(memTx)
			mem.logger.Info("Added good transaction",
				"tx", txID(tx),
				"res", r,
				"height", memTx.height,
				"total", mem.Size(),
			)
			mem.notifyTxsAvailable()
		} else {
			// ignore bad transaction
			mem.logger.Info("Rejected bad transaction",
				"tx", txID(tx), "peerID", peerP2PID, "res", r, "err", postCheckErr)
			mem.metrics.FailedTxs.Add(1)
			// remove from cache (it might be good later)
			mem.cache.Remove(tx)
		}
	default:
		// ignore other messages
	}
}

// callback, which is called after the app rechecked the tx.
//
// The case where the app checks the tx for the first time is handled by the
// ResCbFirstTime callback.
func (mem *CListMempool) resCbRecheck(req *abci.Request, res *abci.Response) {
	switch r := res.Value.(type) {
	case *abci.Response_CheckTx:
		tx := req.GetCheckTx().Tx
		memTx := mem.recheckCursor.Value.(*mempoolTx)
		if !bytes.Equal(tx, memTx.tx) {
			panic(fmt.Sprintf(
				"Unexpected tx response from proxy during recheck\nExpected %X, got %X",
				memTx.tx,
				tx))
		}
		var postCheckErr error
		if mem.postCheck != nil {
			postCheckErr = mem.postCheck(tx, r.CheckTx)
		}
		if (r.CheckTx.Code == abci.CodeTypeOK) && postCheckErr == nil {
			// Good, nothing to do.
		} else {
			// Tx became invalidated due to newly committed block.
			mem.logger.Info("Tx is no longer valid", "tx", txID(tx), "res", r, "err", postCheckErr)
			// NOTE: we remove tx from the cache because it might be good later
			mem.removeTx(tx, mem.recheckCursor, true)
		}
		if mem.recheckCursor == mem.recheckEnd {
			mem.recheckCursor = nil
		} else {
			mem.recheckCursor = mem.recheckCursor.Next()
		}
		if mem.recheckCursor == nil {
			// Done!
			atomic.StoreInt32(&mem.rechecking, 0)
			mem.logger.Info("Done rechecking txs")

			// incase the recheck removed all txs
			if mem.Size() > 0 {
				mem.notifyTxsAvailable()
			}
		}
	default:
		// ignore other messages
	}
}

func (mem *CListMempool) TxsAvailable() <-chan struct{} {
	return mem.txsAvailable
}

// Function to return Txs that as far as we know,
// this peer hasn't seen. We maintain a map from
// peer id to pointer in the list. We can know that the
// peer id is stale because it points to an invalid element
// (behind the back of the list). If the element pointed to
// is removed normally, the pointer can follow still valid
// forward references in the list.
func (mem *CListMempool) GetNewTxs(peerID uint16, max int) (ret []*types.Tx) {

	// There isn't any new Txs
	if mem.txs.Len() == 0 {
		return
	}

	// Lock here protects peer pointers map and front of clist
	mem.proxyMtx.Lock()

	// Does this peer already exist in the map? If not, create and
	// point to the front of the list
	if _, exists := mem.peerPointers[peerID]; !exists {
		front := mem.txs.Front()
		if front == nil {
			mem.logger.Error(fmt.Sprintf("Front of mempool was empty when it shouldn't be. Note: len: %v", mem.txs.Len())) 
			mem.proxyMtx.Unlock()
			return
		}
		mem.peerPointers[peerID] = peerPointer{mem.txs.Front(), make([]*clist.CElement, 0)}
		ret = append(ret, &front.Value.(*mempoolTx).tx) // corner case where we want this + next
	}

	peerPointer := mem.peerPointers[peerID]
	mem.proxyMtx.Unlock()

	// Find the first non-removed mempool entry
	peerPointer.Element = advanceUntilNotRemoved(peerPointer.Element)

	// Collect up to max Txs. First, see if there are any priority Txs
	for len(peerPointer.PriorityTxs) > 0 {

		// Get last element
		priLen := len(peerPointer.PriorityTxs)
		e := peerPointer.PriorityTxs[priLen-1]

		memTx := e.Value.(*mempoolTx)

		if _, ok := memTx.senders.Load(peerID); !ok {
			ret = append(ret, &memTx.tx)
		}

		// remove last element and nil to force garbage collection (important!)
		peerPointer.PriorityTxs[priLen-1] = nil
		peerPointer.PriorityTxs = peerPointer.PriorityTxs[:priLen-1]

		if len(ret) >= max {
			break
		}
	}

	next := peerPointer.Element.Next()

	for next != nil && len(ret) < max {
		// Only add/return this if the peer hasn't seen it
		memTx := next.Value.(*mempoolTx)

		if _, ok := memTx.senders.Load(peerID); !ok {
			ret = append(ret, &memTx.tx)
		}
		peerPointer.Element = next
		next = next.Next()
	}

	// Update position in the map
	mem.proxyMtx.Lock()
	mem.peerPointers[peerID] = peerPointer
	mem.proxyMtx.Unlock()
	return
}

// Given a non-nil element, follow its references forward until a non-removed
// one is found. Never return nil. Do not modify the element
func advanceUntilNotRemoved(elem *clist.CElement) (ret *clist.CElement) {
	ret = elem

	for elem != nil && ret.Removed() {
		ret = elem
		elem = elem.Next()
	}
	return
}

func (mem *CListMempool) notifyTxsAvailable() {
	if mem.Size() == 0 {
		panic("notified txs available but mempool is empty!")
	}
	if mem.txsAvailable != nil && !mem.notifiedTxsAvailable {
		// channel cap is 1, so this will send once
		mem.notifiedTxsAvailable = true
		select {
		case mem.txsAvailable <- struct{}{}:
		default:
		}
	}
}

func (mem *CListMempool) ReapMaxBytesMaxGas(maxBytes, maxGas int64, fallbackMode bool) types.Txs {
	mem.proxyMtx.Lock()
	defer mem.proxyMtx.Unlock()

	for atomic.LoadInt32(&mem.rechecking) > 0 {
		// TODO: Something better?
		time.Sleep(time.Millisecond * 10)
	}

	var totalBytes int64
	var totalGas int64
	// TODO: we will get a performance boost if we have a good estimate of avg
	// size per tx, and set the initial capacity based off of that.
	// txs := make([]types.Tx, 0, tmmath.MinInt(mem.txs.Len(), max/mem.avgTxSize))
	txs := make([]types.Tx, 0, mem.txs.Len())
	for e := mem.txs.Front(); e != nil; e = e.Next() {
		memTx := e.Value.(*mempoolTx)

		// Since we know all priority txs should be at the front, we can
		// stop reaping once we find one that is not, when in fallback mode
		if fallbackMode && !isPriority(memTx.tx) {
			return txs
		}

		// Check total size requirement
		aminoOverhead := types.ComputeAminoOverhead(memTx.tx, 1)
		if maxBytes > -1 && totalBytes+int64(len(memTx.tx))+aminoOverhead > maxBytes {
			return txs
		}
		totalBytes += int64(len(memTx.tx)) + aminoOverhead
		// Check total gas requirement.
		// If maxGas is negative, skip this check.
		// Since newTotalGas < masGas, which
		// must be non-negative, it follows that this won't overflow.
		newTotalGas := totalGas + memTx.gasWanted
		if maxGas > -1 && newTotalGas > maxGas {
			return txs
		}
		totalGas = newTotalGas
		txs = append(txs, memTx.tx)
	}
	return txs
}

// Requires Lock() is held
// removes any peer pointers that point to a removed element
func (mem *CListMempool) cleanPeerPointers() {
	for key, value := range mem.peerPointers {
		if value.Element.Removed() {
			delete(mem.peerPointers, key)
		}
	}
}

// Safe for concurrent use by multiple goroutines.
func (mem *CListMempool) ReapMaxTxs(max int) types.Txs {
	mem.proxyMtx.Lock()
	defer mem.proxyMtx.Unlock()

	if max < 0 {
		max = mem.txs.Len()
	}

	for atomic.LoadInt32(&mem.rechecking) > 0 {
		// TODO: Something better?
		time.Sleep(time.Millisecond * 10)
	}

	txs := make([]types.Tx, 0, tmmath.MinInt(mem.txs.Len(), max))
	for e := mem.txs.Front(); e != nil && len(txs) <= max; e = e.Next() {
		memTx := e.Value.(*mempoolTx)
		txs = append(txs, memTx.tx)
	}
	return txs
}

// Lock() must be held by the caller during execution.
func (mem *CListMempool) Update(
	height int64,
	txs types.Txs,
	deliverTxResponses []*abci.ResponseDeliverTx,
	preCheck PreCheckFunc,
	postCheck PostCheckFunc,
) error {
	// Set height
	mem.height = height
	mem.notifiedTxsAvailable = false

	if preCheck != nil {
		mem.preCheck = preCheck
	}
	if postCheck != nil {
		mem.postCheck = postCheck
	}

	// Housekeeping: remove peer clist references that point to a removed
	// element since it is likely it is stale (points to TX most likely removed
	// during prior call to Update()
	mem.cleanPeerPointers()

	for i, tx := range txs {
		if deliverTxResponses[i].Code == abci.CodeTypeOK {
			// Add valid committed tx to the cache (if missing).
			_ = mem.cache.Push(tx)
		} else {
			// Allow invalid transactions to be resubmitted.
			mem.cache.Remove(tx)
		}

		// Remove committed tx from the mempool.
		//
		// Note an evil proposer can drop valid txs!
		// Mempool before:
		//   100 -> 101 -> 102
		// Block, proposed by an evil proposer:
		//   101 -> 102
		// Mempool after:
		//   100
		// https://github.com/tendermint/tendermint/issues/3322.
		if e, ok := mem.txsMap.Load(txKey(tx)); ok {
			mem.removeTx(tx, e.(*clist.CElement), false)
		}
	}

	// Either recheck non-committed txs to see if they became invalid
	// or just notify there're some txs left.
	if mem.Size() > 0 {
		if mem.config.Recheck {
			mem.logger.Info("Recheck txs", "numtxs", mem.Size(), "height", height)
			mem.recheckTxs()
			// At this point, mem.txs are being rechecked.
			// mem.recheckCursor re-scans mem.txs and possibly removes some txs.
			// Before mem.Reap(), we should wait for mem.recheckCursor to be nil.
		} else {
			mem.notifyTxsAvailable()
		}
	}

	// Update metrics
	mem.metrics.Size.Set(float64(mem.Size()))
	mem.metrics.SizeBytes.Set(float64(mem.TxsBytes()))

	return nil
}

func (mem *CListMempool) recheckTxs() {
	if mem.Size() == 0 {
		panic("recheckTxs is called, but the mempool is empty")
	}

	atomic.StoreInt32(&mem.rechecking, 1)
	mem.recheckCursor = mem.txs.Front()
	mem.recheckEnd = mem.txs.Back()

	// Push txs to proxyAppConn
	// NOTE: globalCb may be called concurrently.
	for e := mem.txs.Front(); e != nil; e = e.Next() {
		memTx := e.Value.(*mempoolTx)
		mem.proxyAppConn.CheckTxAsync(abci.RequestCheckTx{
			Tx:   memTx.tx,
			Type: abci.CheckTxType_Recheck,
		})
	}

	mem.proxyAppConn.FlushAsync()
}

//--------------------------------------------------------------------------------

// mempoolTx is a transaction that successfully ran
type mempoolTx struct {
	height    int64    // height that this tx had been validated in
	gasWanted int64    // amount of gas this tx states it will require
	tx        types.Tx //

	// ids of peers who've sent us this tx (as a map for quick lookups).
	// senders: PeerID -> bool
	senders sync.Map
}

// Height returns the height for this transaction
func (memTx *mempoolTx) Height() int64 {
	return atomic.LoadInt64(&memTx.height)
}

//--------------------------------------------------------------------------------

type txCache interface {
	Reset()
	Push(tx types.Tx) bool
	Remove(tx types.Tx)
}

// mapTxCache maintains a LRU cache of transactions. This only stores the hash
// of the tx, due to memory concerns.
type mapTxCache struct {
	mtx      sync.Mutex
	size     int
	cacheMap map[[sha256.Size]byte]*list.Element
	list     *list.List
}

var _ txCache = (*mapTxCache)(nil)

// newMapTxCache returns a new mapTxCache.
func newMapTxCache(cacheSize int) *mapTxCache {
	return &mapTxCache{
		size:     cacheSize,
		cacheMap: make(map[[sha256.Size]byte]*list.Element, cacheSize),
		list:     list.New(),
	}
}

// Reset resets the cache to an empty state.
func (cache *mapTxCache) Reset() {
	cache.mtx.Lock()
	cache.cacheMap = make(map[[sha256.Size]byte]*list.Element, cache.size)
	cache.list.Init()
	cache.mtx.Unlock()
}

// Push adds the given tx to the cache and returns true. It returns
// false if tx is already in the cache.
func (cache *mapTxCache) Push(tx types.Tx) bool {
	cache.mtx.Lock()
	defer cache.mtx.Unlock()

	// Use the tx hash in the cache
	txHash := txKey(tx)
	if moved, exists := cache.cacheMap[txHash]; exists {
		cache.list.MoveToBack(moved)
		return false
	}

	if cache.list.Len() >= cache.size {
		popped := cache.list.Front()
		poppedTxHash := popped.Value.([sha256.Size]byte)
		delete(cache.cacheMap, poppedTxHash)
		if popped != nil {
			cache.list.Remove(popped)
		}
	}
	e := cache.list.PushBack(txHash)
	cache.cacheMap[txHash] = e
	return true
}

// Remove removes the given tx from the cache.
func (cache *mapTxCache) Remove(tx types.Tx) {
	cache.mtx.Lock()
	txHash := txKey(tx)
	popped := cache.cacheMap[txHash]
	delete(cache.cacheMap, txHash)
	if popped != nil {
		cache.list.Remove(popped)
	}

	cache.mtx.Unlock()
}

type nopTxCache struct{}

var _ txCache = (*nopTxCache)(nil)

func (nopTxCache) Reset()             {}
func (nopTxCache) Push(types.Tx) bool { return true }
func (nopTxCache) Remove(types.Tx)    {}

//--------------------------------------------------------------------------------

// txKey is the fixed length array sha256 hash used as the key in maps.
func txKey(tx types.Tx) [sha256.Size]byte {
	return sha256.Sum256(tx)
}

// txID is the hex encoded hash of the bytes as a types.Tx.
func txID(tx []byte) string {
	return fmt.Sprintf("%X", types.Tx(tx).Hash())
}
