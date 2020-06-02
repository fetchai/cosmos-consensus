package beacon

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/tendermint/go-amino"
	cmn "github.com/tendermint/tendermint/libs/common"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
)

const (
	// StateChannel for broadcasting to peers you computed entropy height
	StateChannel = byte(0x80)
	// EntropyChannel along which signature shares on previous entropy are communicated
	EntropyChannel = byte(0x81)

	maxMsgSize = 1048576 // 1MB; NOTE/TODO: keep in sync with types.PartSet sizes.
)

//-----------------------------------------------------------------------------

// Reactor defines a reactor for the random beacon service.
type Reactor struct {
	p2p.BaseReactor // BaseService + p2p.Switch

	entropyGen *EntropyGenerator

	mtx      sync.RWMutex
	fastSync bool

	// Access blockchain through RPC for catching up peers
	blockStore sm.BlockStoreRPC
}

// NewReactor returns a new Reactor with the given entropyGenerator.
func NewReactor(entropyGenerator *EntropyGenerator, fastSync bool, blockStore sm.BlockStoreRPC) *Reactor {
	if entropyGenerator == nil {
		panic(fmt.Sprintf("NewReactor with nil entropy generator"))
	}
	BeaconR := &Reactor{
		entropyGen: entropyGenerator,
		fastSync:   fastSync,
		blockStore: blockStore,
	}

	BeaconR.BaseReactor = *p2p.NewBaseReactor("Reactor", BeaconR)

	return BeaconR
}

// OnStart implements BaseService by subscribing to events, which later will be
// broadcasted to other peers and starting state if we're not in fast sync.
func (beaconR *Reactor) OnStart() error {
	beaconR.Logger.Info("Reactor ", "fastSync", beaconR.fastSync)

	beaconR.subscribeToBroadcastEvents()
	if !beaconR.fastSync {
		// If no previous entropy has been set then look back through chain to find
		// either genesis or last computed entropy
		if beaconR.entropyGen.lastComputedEntropyHeight == -1 {
			beaconR.findAndSetLastEntropy(beaconR.entropyGen.lastBlockHeight)
		}
		return beaconR.entropyGen.Start()
	}

	return nil
}

// OnStop implements BaseService by unsubscribing from events and stopping
// state.
func (beaconR *Reactor) OnStop() {
	beaconR.unsubscribeFromBroadcastEvents()
	if beaconR.entropyGen.IsRunning() {
		beaconR.entropyGen.Stop()
		beaconR.entropyGen.wait()
	}
}

// SwitchToConsensus from fast sync, when no entropy is generated, to consensus mode by resetting the
// last computed entropy
func (beaconR *Reactor) SwitchToConsensus(state sm.State) {
	beaconR.Logger.Info("SwitchToConsensus")

	lastBlockHeight := state.LastBlockHeight

	if len(state.LastComputedEntropy) == 0 {
		beaconR.findAndSetLastEntropy(lastBlockHeight)
	} else {
		beaconR.entropyGen.SetLastComputedEntropy(lastBlockHeight, state.LastComputedEntropy)
	}

	beaconR.entropyGen.setLastBlockHeight(lastBlockHeight)

	beaconR.mtx.Lock()
	beaconR.fastSync = false
	beaconR.mtx.Unlock()

	err := beaconR.entropyGen.Start()
	if err != nil {
		panic(fmt.Sprintf(`Failed to start entropy generator: %v

conS:
%+v

conR:
%+v`, err, beaconR.entropyGen, beaconR))
	}
}

// GetChannels implements Reactor
func (beaconR *Reactor) GetChannels() []*p2p.ChannelDescriptor {
	return []*p2p.ChannelDescriptor{
		{
			ID:                  StateChannel,
			Priority:            5,
			SendQueueCapacity:   100,
			RecvMessageCapacity: maxMsgSize,
		},
		{
			ID:                  EntropyChannel,
			Priority:            5,
			SendQueueCapacity:   100,
			RecvMessageCapacity: maxMsgSize,
		},
	}
}

// getFastSync returns whether the reactor is in fast-sync mode.
func (beaconR *Reactor) getFastSync() bool {
	beaconR.mtx.RLock()
	defer beaconR.mtx.RUnlock()
	return beaconR.fastSync
}

// Given that we are on block height, set the entropy generator with
// the last block that had entropy
func (beaconR *Reactor) findAndSetLastEntropy(height int64) {

	for height > 0 {

		blockEntropy := beaconR.blockStore.LoadBlockMeta(height).Header.Entropy.GroupSignature
		if len(blockEntropy) != 0 {
			beaconR.entropyGen.SetLastComputedEntropy(height, blockEntropy)
			break
		}
		height--
	}
}

// InitPeer implements Reactor by creating a state for the peer.
func (beaconR *Reactor) InitPeer(peer p2p.Peer) p2p.Peer {
	beaconR.Logger.Debug("InitPeer", "peer", peer)
	peerState := NewPeerState(peer).SetLogger(beaconR.Logger)
	peer.Set(types.BeaconPeerStateKey, peerState)
	return peer
}

// AddPeer implements Reactor by spawning multiple gossiping goroutines for the
// peer.
func (beaconR *Reactor) AddPeer(peer p2p.Peer) {
	beaconR.Logger.Debug("AddPeer", "peer", peer)
	if !beaconR.IsRunning() {
		return
	}
	peerState, ok := peer.Get(types.BeaconPeerStateKey).(*PeerState)
	if !ok {
		panic(fmt.Sprintf("peer %v has no state", peer))
	}

	// Begin routines for this peer.
	go beaconR.gossipEntropySharesRoutine(peer, peerState)
}

// RemovePeer is a noop.
func (beaconR *Reactor) RemovePeer(peer p2p.Peer, reason interface{}) {
	if !beaconR.IsRunning() {
		return
	}
}

// Receive implements Reactor and processes either state or entropy share messages
func (beaconR *Reactor) Receive(chID byte, src p2p.Peer, msgBytes []byte) {
	if !beaconR.IsRunning() {
		beaconR.Logger.Debug("Receive", "src", src, "chId", chID, "bytes", msgBytes)
		return
	}

	msg, err := decodeMsg(msgBytes)
	if err != nil {
		beaconR.Logger.Error("Error decoding message", "src", src, "chId", chID, "msg", msg, "err", err, "bytes", msgBytes)
		beaconR.Switch.StopPeerForError(src, err)
		return
	}

	if err = msg.ValidateBasic(); err != nil {
		beaconR.Logger.Error("Peer sent us invalid msg", "peer", src, "msg", msg, "err", err)
		beaconR.Switch.StopPeerForError(src, err)
		return
	}

	beaconR.Logger.Debug("Receive", "src", src, "chId", chID, "msg", msg)

	// Get peer states
	ps, ok := src.Get(types.BeaconPeerStateKey).(*PeerState)
	if !ok {
		panic(fmt.Sprintf("Peer %v has no state", src))
	}

	switch chID {
	case StateChannel:
		switch msg := msg.(type) {
		case *NewEntropyHeightMessage:
			ps.setLastComputedEntropyHeight(msg.Height)
		default:
			beaconR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
		}

	case EntropyChannel:
		if beaconR.getFastSync() || !beaconR.entropyGen.isSigningEntropy() {
			beaconR.Logger.Info("Ignoring message received during fastSync/entropy generator has no keys", "msg", msg)
			return
		}
		switch msg := msg.(type) {
		case *EntropyShareMessage:
			index, _ := beaconR.entropyGen.aeon.validators.GetByAddress(msg.SignerAddress)
			ps.hasEntropyShare(msg.EntropyShare.Height, index, beaconR.entropyGen.aeon.validators.Size())
			beaconR.entropyGen.applyEntropyShare(msg.EntropyShare)
		case *ComputedEntropyMessage:
			beaconR.entropyGen.applyComputedEntropy(msg.Height, msg.GroupSignature)
		default:
			beaconR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
		}

	default:
		beaconR.Logger.Error(fmt.Sprintf("Unknown chId %X", chID))
	}
}

// subscribeToBroadcastEvents subscribes for has entropy share messages
func (beaconR *Reactor) subscribeToBroadcastEvents() {
	const subscriber = "beacon-reactor"
	beaconR.entropyGen.evsw.AddListenerForEvent(subscriber, types.EventComputedEntropy,
		func(data tmevents.EventData) {
			beaconR.broadcastNewEntropyHeightMessage(data.(int64))
		})
}

func (beaconR *Reactor) unsubscribeFromBroadcastEvents() {
	const subscriber = "beacon-reactor"
	beaconR.entropyGen.evsw.RemoveListener(subscriber)
}

func (beaconR *Reactor) broadcastNewEntropyHeightMessage(height int64) {
	esMsg := &NewEntropyHeightMessage{
		Height: height,
	}
	beaconR.Switch.Broadcast(StateChannel, cdc.MustMarshalBinaryBare(esMsg))
}

//--------------------------------------

func (beaconR *Reactor) gossipEntropySharesRoutine(peer p2p.Peer, ps *PeerState) {
	logger := beaconR.Logger.With("peer", peer)
	// Send peer most recent computed entropy if not fast syncing
	if !beaconR.getFastSync() {
		peer.Send(StateChannel, cdc.MustMarshalBinaryBare(&NewEntropyHeightMessage{Height: beaconR.entropyGen.getLastBlockHeight()}))
	}

OUTER_LOOP:
	for {
		// Manage disconnects from self or peer.
		if !peer.IsRunning() || !beaconR.IsRunning() {
			logger.Info("Stopping gossipEntropySharesRoutine for peer", "beacon running", beaconR.IsRunning(), "peer running", peer.IsRunning())
			return
		}

		nextEntropyHeight := ps.getLastComputedEntropyHeight() + 1
		// Use block chain for entropy that has been included in block
		if nextEntropyHeight < beaconR.entropyGen.getLastBlockHeight() {
			block := beaconR.blockStore.LoadBlockMeta(nextEntropyHeight)
			if block != nil && len(block.Header.Entropy.GroupSignature) != 0 {
				// Send peer entropy from block store
				ps.sendEntropy(nextEntropyHeight, block.Header.Entropy.GroupSignature)
				time.Sleep(beaconR.entropyGen.consensusConfig.PeerGossipSleepDuration)
				continue OUTER_LOOP
			}
		}
		entropy := beaconR.entropyGen.getComputedEntropy(nextEntropyHeight)
		if entropy != nil {
			ps.sendEntropy(nextEntropyHeight, entropy)
			time.Sleep(beaconR.entropyGen.consensusConfig.PeerGossipSleepDuration)
			continue OUTER_LOOP
		}
		if beaconR.entropyGen.isSigningEntropy() {
			ps.pickSendEntropyShare(nextEntropyHeight,
				beaconR.entropyGen.getEntropyShares(nextEntropyHeight),
				beaconR.entropyGen.aeon.validators.Size())
		}

		time.Sleep(beaconR.entropyGen.consensusConfig.PeerGossipSleepDuration)
		continue OUTER_LOOP
	}
}

// String returns a string representation of the Reactor.
// NOTE: For now, it is just a hard-coded string to avoid accessing unprotected shared variables.
// TODO: improve!
func (beaconR *Reactor) String() string {
	// better not to access shared variables
	return beaconR.StringIndented("")
}

// StringIndented returns an indented string representation of the Reactor
func (beaconR *Reactor) StringIndented(indent string) string {
	s := "BeaconReactor{\n"
	for _, peer := range beaconR.Switch.Peers().List() {
		ps, ok := peer.Get(types.BeaconPeerStateKey).(*PeerState)
		if !ok {
			panic(fmt.Sprintf("Peer %v has no state", peer))
		}
		s += indent + "  " + ps.StringIndented(indent+"  ") + "\n"
	}
	s += indent + "}"
	return s
}

//-----------------------------------------------------------------------------

// PeerState keeps track of what signature shares peer has seen
// Be mindful of what you Expose.
type PeerState struct {
	peer   p2p.Peer
	logger log.Logger

	mtx sync.Mutex // NOTE: Modify below using setters, never directly.

	// Keep track of entropy shares for each block height
	entropyShares             map[int64]*cmn.BitArray
	lastComputedEntropyHeight int64
}

// NewPeerState returns a new PeerState for the given Peer
func NewPeerState(peer p2p.Peer) *PeerState {
	return &PeerState{
		peer:                      peer,
		logger:                    log.NewNopLogger(),
		entropyShares:             make(map[int64]*cmn.BitArray),
		lastComputedEntropyHeight: types.GenesisHeight,
	}
}

// SetLogger allows to set a logger on the peer state. Returns the peer state
// itself.
func (ps *PeerState) SetLogger(logger log.Logger) *PeerState {
	ps.logger = logger
	return ps
}

// getLastComputedEntropyHeight returns last height peer had enough
// shares to compute entropy
func (ps *PeerState) getLastComputedEntropyHeight() int64 {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	return ps.lastComputedEntropyHeight
}

// setLastComputedEntropyHeight sets the last height peer states it computed
// entropy for
func (ps *PeerState) setLastComputedEntropyHeight(height int64) {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	if height > ps.lastComputedEntropyHeight {
		ps.lastComputedEntropyHeight = height
	} else {
		ps.logger.Debug("SetLastComputedEntropyHeight resetting to past", "peerCurrentHeight", ps.lastComputedEntropyHeight, "resetHeight", height)
	}
}

func (ps *PeerState) sendEntropy(nextEntropyHeight int64, entropy types.ThresholdSignature) {
	// Send peer entropy from block store
	ps.logger.Debug("sendEntropy", "ps", ps, "height", nextEntropyHeight)
	msg := &ComputedEntropyMessage{Height: nextEntropyHeight, GroupSignature: entropy}
	ps.peer.Send(EntropyChannel, cdc.MustMarshalBinaryBare(msg))
}

// pickSendEntropyShare sends all entropy shares that peer needs
func (ps *PeerState) pickSendEntropyShare(nextEntropyHeight int64, entropyShares map[uint]types.EntropyShare, numValidators int) {
	for {
		if key, value, ok := ps.pickEntropyShare(nextEntropyHeight, entropyShares); ok {
			msg := &EntropyShareMessage{value}
			if ps.peer.Send(EntropyChannel, cdc.MustMarshalBinaryBare(msg)) {
				ps.logger.Debug("pickSendEntropyShare succeeded", "ps", ps, "height", value.Height, "share index", key)
				ps.hasEntropyShare(nextEntropyHeight, int(key), numValidators)
			}
		} else {
			return
		}
	}
}

func (ps *PeerState) pickEntropyShare(nextEntropyHeight int64, entropyShares map[uint]types.EntropyShare) (uint, *types.EntropyShare, bool) {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	if entropyShares == nil {
		return 0, nil, false
	}
	if len(entropyShares) == 0 {
		return 0, nil, false
	}
	if ps.lastComputedEntropyHeight+1 != nextEntropyHeight {
		ps.logger.Debug("PickSendEntropyShare height mismatch", "peer height", ps.lastComputedEntropyHeight, "working height", nextEntropyHeight)
		return 0, nil, false
	}
	peerEntropyShares := ps.entropyShares[nextEntropyHeight]

	for key, value := range entropyShares {
		if !peerEntropyShares.GetIndex(int(key)) {
			return key, &value, true
		}
	}
	return 0, nil, false
}

// hasEntropyShare marks the peer as having a entropy share at given height from a particular validator index
func (ps *PeerState) hasEntropyShare(height int64, index int, numValidators int) {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	if index < 0 {
		return
	}

	// Make sure bit array is initialised
	if ps.entropyShares[height] == nil {
		ps.entropyShares[height] = cmn.NewBitArray(numValidators)
	}

	ps.entropyShares[height].SetIndex(index, true)
}

// ToJSON returns a json of PeerState, marshalled using go-amino.
func (ps *PeerState) ToJSON() ([]byte, error) {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	return cdc.MarshalJSON(ps)
}

// String returns a string representation of the PeerState
func (ps *PeerState) String() string {
	return ps.StringIndented("")
}

// StringIndented returns a string representation of the PeerState
func (ps *PeerState) StringIndented(indent string) string {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()
	return fmt.Sprintf(`PeerState{
%s  Key        %v
%s  LastComputedEntropyHeight %v
%s}`,
		indent, ps.peer.ID(),
		indent, ps.lastComputedEntropyHeight,
		indent)
}

//-----------------------------------------------------------------------------
// Messages

// Message is a message that can be sent and received on the Reactor
type Message interface {
	ValidateBasic() error
}

// RegisterMessages registers entropy share message
func RegisterMessages(cdc *amino.Codec) {
	cdc.RegisterInterface((*Message)(nil), nil)
	cdc.RegisterConcrete(&NewEntropyHeightMessage{}, "tendermint/NewEntropyHeight", nil)
	cdc.RegisterConcrete(&EntropyShareMessage{}, "tendermint/EntropyShare", nil)
	cdc.RegisterConcrete(&ComputedEntropyMessage{}, "tendermint/ComputedEntropy", nil)
}

func decodeMsg(bz []byte) (msg Message, err error) {
	if len(bz) > maxMsgSize {
		return msg, fmt.Errorf("msg exceeds max size (%d > %d)", len(bz), maxMsgSize)
	}
	err = cdc.UnmarshalBinaryBare(bz, &msg)
	return
}

//-------------------------------------

// NewEntropyHeightMessage contains last entropy height computed
type NewEntropyHeightMessage struct {
	Height int64
}

// ValidateBasic performs basic validation.
func (m *NewEntropyHeightMessage) ValidateBasic() error {
	if m.Height < types.GenesisHeight {
		return errors.New("invalid Height")
	}

	return nil
}

// String returns a string representation.
func (m *NewEntropyHeightMessage) String() string {
	return fmt.Sprintf("[NewEntropyHeightMessage %v]", m.Height)
}

//-------------------------------------

// EntropyShareMessage is for computing DRB
type EntropyShareMessage struct {
	*types.EntropyShare
}

// ValidateBasic performs basic validation.
func (m *EntropyShareMessage) ValidateBasic() error {
	return m.EntropyShare.ValidateBasic()
}

// String returns a string representation.
func (m *EntropyShareMessage) String() string {
	return fmt.Sprintf("[EntropyShare %v]", m.EntropyShare)
}

//-------------------------------------

// ComputedEntropyMessage is for catching up peers
type ComputedEntropyMessage struct {
	Height         int64
	GroupSignature types.ThresholdSignature
}

// ValidateBasic performs basic validation.
func (m *ComputedEntropyMessage) ValidateBasic() error {
	if m.Height < types.GenesisHeight {
		return errors.New("invalid Height")
	}
	if len(m.GroupSignature) > types.MaxThresholdSignatureSize {
		return fmt.Errorf("expected GroupSignature size be max %d bytes, got %d bytes",
			types.MaxThresholdSignatureSize,
			len(m.GroupSignature),
		)
	}
	return nil
}

// String returns a string representation.
func (m *ComputedEntropyMessage) String() string {
	return fmt.Sprintf("[ComputedEntropy %v/%v]", m.Height, m.GroupSignature)
}
