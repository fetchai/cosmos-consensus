package clist

//import (
//"sync"
//"github.com/tendermint/tendermint/libs/clist"
//)

// Define a structure that holds high or low priority items, returning high
// priority items first (wraps/extends the clist behaviour).
// It does this by keeping a reference to where in the list the divide between low
// and high priority items are
type PriorityPool struct {
	txs              *CList // concurrent linked-list of other txs
	back_of_priority *CElement
}

func NewPriorityPool() *PriorityPool {
	pool := PriorityPool{New(), nil}

	return &pool
}

func (pool PriorityPool) Len() int {
	return pool.txs.Len()
}

func (pool *PriorityPool) Front() *CElement {
	return pool.txs.Front()
}

func (pool *PriorityPool) Back() *CElement {
	return pool.txs.Back()
}

func (pool *PriorityPool) PushBack(v interface{}, priority bool) *CElement {
	if !priority {
		return pool.txs.PushBack(v)
	}

	if pool.back_of_priority == nil {
		pool.back_of_priority = pool.Front()
	}

	pool.back_of_priority = pool.txs.Insert(v, pool.back_of_priority)

	return pool.back_of_priority
}

func (pool *PriorityPool) Remove(e *CElement) interface{} {
	return pool.txs.Remove(e)
}

func (pool *PriorityPool) WaitChan() <-chan struct{} {
	return pool.txs.WaitChan()
}
