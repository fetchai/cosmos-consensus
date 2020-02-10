package beacon

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/libs/bits"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/types"
	"reflect"
	"sync"
	"time"
)

const (
	StateChannel      = byte(0x80)
	EntropyChannel     = byte(0x81)

	maxMsgSize = 1048576 // 1MB; NOTE/TODO: keep in sync with types.PartSet sizes.

	PeerGossipSleepDuration = 100 * time.Millisecond
)

//-----------------------------------------------------------------------------

// Reactor defines a reactor for the random beacon service.
type Reactor struct {
	p2p.BaseReactor // BaseService + p2p.Switch

	entropyGen *EntropyGenerator

	mtx      sync.RWMutex
	fastSync bool
	eventBus *types.EventBus
}

type ReactorOption func(*Reactor)

// NewReactor returns a new Reactor with the given
// entropyGenerator.
func NewReactor(entropyGenerator *EntropyGenerator, options ...ReactorOption) *Reactor {
	conR := &Reactor{
		entropyGen:     entropyGenerator,
	}
	conR.BaseReactor = *p2p.NewBaseReactor("Reactor", conR)

	for _, option := range options {
		option(conR)
	}

	return conR
}

// OnStart implements BaseService by subscribing to events, which later will be
// broadcasted to other peers and starting state if we're not in fast sync.
func (conR *Reactor) OnStart() error {
	conR.Logger.Info("Reactor ")

	conR.subscribeToBroadcastEvents()

	err := conR.entropyGen.Start()
	if err != nil {
		return err
	}

	return nil
}

// OnStop implements BaseService by unsubscribing from events and stopping
// state.
func (conR *Reactor) OnStop() {
	conR.unsubscribeFromBroadcastEvents()
	conR.entropyGen.Stop()
}

// GetChannels implements Reactor
func (conR *Reactor) GetChannels() []*p2p.ChannelDescriptor {
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

// InitPeer implements Reactor by creating a state for the peer.
func (conR *Reactor) InitPeer(peer p2p.Peer) p2p.Peer {
	peerState := NewPeerState(peer).SetLogger(conR.Logger)
	peer.Set(types.PeerStateKey, peerState)
	return peer
}

// AddPeer implements Reactor by spawning multiple gossiping goroutines for the
// peer.
func (conR *Reactor) AddPeer(peer p2p.Peer) {
	if !conR.IsRunning() {
		return
	}

	peerState, ok := peer.Get(types.PeerStateKey).(*PeerState)
	if !ok {
		panic(fmt.Sprintf("peer %v has no state", peer))
	}
	// Begin routines for this peer.
	go conR.gossipEntropySharesRoutine(peer, peerState)
}

// RemovePeer is a noop.
func (conR *Reactor) RemovePeer(peer p2p.Peer, reason interface{}) {
	if !conR.IsRunning() {
		return
	}
	// TODO
	// ps, ok := peer.Get(PeerStateKey).(*PeerState)
	// if !ok {
	// 	panic(fmt.Sprintf("Peer %v has no state", peer))
	// }
	// ps.Disconnect()
}

// Receive implements Reactor and processes either state or entropy share messages
func (conR *Reactor) Receive(chID byte, src p2p.Peer, msgBytes []byte) {
	if !conR.IsRunning() {
		conR.Logger.Debug("Receive", "src", src, "chId", chID, "bytes", msgBytes)
		return
	}

	msg, err := decodeMsg(msgBytes)
	if err != nil {
		conR.Logger.Error("Error decoding message", "src", src, "chId", chID, "msg", msg, "err", err, "bytes", msgBytes)
		conR.Switch.StopPeerForError(src, err)
		return
	}

	if err = msg.ValidateBasic(); err != nil {
		conR.Logger.Error("Peer sent us invalid msg", "peer", src, "msg", msg, "err", err)
		conR.Switch.StopPeerForError(src, err)
		return
	}

	conR.Logger.Debug("Receive", "src", src, "chId", chID, "msg", msg)

	// Get peer states
	ps, ok := src.Get(types.PeerStateKey).(*PeerState)
	if !ok {
		panic(fmt.Sprintf("Peer %v has no state", src))
	}

	switch chID {
	case StateChannel:
		switch msg := msg.(type) {
		case *HasEntropyShareMessage:
			index, _ := conR.entropyGen.Validators.GetByAddress(msg.SignerAddress)
			ps.HasEntropyShare(msg.Height, index, conR.entropyGen.Validators.Size())
		default:
			conR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
		}

	case EntropyChannel:
		switch msg := msg.(type) {
		case *EntropyShareMessage:
			if conR.entropyGen != nil {
				err := conR.entropyGen.ApplyEntropyShare(msg.EntropyShare)
				if err == nil {
					conR.entropyGen.evsw.FireEvent(EventEntropyShare, msg.EntropyShare)
				}
			}
		default:
			conR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
		}

	default:
		conR.Logger.Error(fmt.Sprintf("Unknown chId %X", chID))
	}
}

//--------------------------------------

// subscribeToBroadcastEvents subscribes for has entropy share messages
func (conR *Reactor) subscribeToBroadcastEvents() {
	const subscriber = "beacon-reactor"
	conR.entropyGen.evsw.AddListenerForEvent(subscriber, EventEntropyShare,
		func(data tmevents.EventData) {
			conR.broadcastHasEntropyShareMessage(data.(*EntropyShare))
		})
}

func (conR *Reactor) unsubscribeFromBroadcastEvents() {
	const subscriber = "beacon-reactor"
	conR.entropyGen.evsw.RemoveListener(subscriber)
}

func (conR *Reactor) broadcastHasEntropyShareMessage(es *EntropyShare) {
	esMsg := &HasEntropyShareMessage{
		Height: es.Height,
		SignerAddress: es.SignerAddress,
	}
	conR.Switch.Broadcast(StateChannel, cdc.MustMarshalBinaryBare(esMsg))
}

func (conR *Reactor) gossipEntropySharesRoutine(peer p2p.Peer, ps *PeerState) {
	logger := conR.Logger.With("peer", peer)

OUTER_LOOP:
	for {
		// Manage disconnects from self or peer.
		if !peer.IsRunning() || !conR.IsRunning() {
			logger.Info("Stopping gossipEntropySharesRoutine for peer")
			return
		}

		if conR.entropyGen != nil {
			peerLastEntropyHeight := ps.GetLastComputedEntropyHeight()
			if ps.PickSendEntropyShare(
				conR.entropyGen.GetEntropyShares(peerLastEntropyHeight+1),
				conR.entropyGen.Validators.Size(),
				conR.entropyGen.GetThreshold()) {
				continue OUTER_LOOP
			}
		}

		time.Sleep(PeerGossipSleepDuration)
		continue OUTER_LOOP
	}
}

// String returns a string representation of the Reactor.
// NOTE: For now, it is just a hard-coded string to avoid accessing unprotected shared variables.
// TODO: improve!
func (conR *Reactor) String() string {
	// better not to access shared variables
	return "EntropyReactor" // conR.StringIndented("")
}

// StringIndented returns an indented string representation of the Reactor
func (conR *Reactor) StringIndented(indent string) string {
	s := "BeaconReactor{\n"
	for _, peer := range conR.Switch.Peers().List() {
		ps, ok := peer.Get(types.PeerStateKey).(*PeerState)
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

	mtx   sync.Mutex             // NOTE: Modify below using setters, never directly.

	// Keep track of entropy shares for each block height
	entropyShares map[int64]*bits.BitArray
	lastComputedEntropyHeight int64
}

// NewPeerState returns a new PeerState for the given Peer
func NewPeerState(peer p2p.Peer) *PeerState {
	return &PeerState{
		peer:   peer,
		logger: log.NewNopLogger(),
		entropyShares: make(map[int64]*bits.BitArray),
		lastComputedEntropyHeight: 0,
	}
}

// SetLogger allows to set a logger on the peer state. Returns the peer state
// itself.
func (ps *PeerState) SetLogger(logger log.Logger) *PeerState {
	ps.logger = logger
	return ps
}

func (ps *PeerState) GetLastComputedEntropyHeight() int64 {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	return ps.lastComputedEntropyHeight
}

func (ps *PeerState) PickSendEntropyShare(peerEntropyShares map[int]EntropyShare, numValidators int, threshold int) bool {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	if peerEntropyShares == nil {
		return false
	}
	if len(peerEntropyShares) == 0 {
		return false
	}

	entropyShares := ps.entropyShares[ps.lastComputedEntropyHeight + 1]
	count := 0
	for i := 0; i < numValidators; i++ {
		if entropyShares.GetIndex(i) {
			count++
		}
	}

	for key, value := range peerEntropyShares {
		if !entropyShares.GetIndex(key) {
			msg := &EntropyShareMessage{&value}
			ps.peer.Send(EntropyChannel, cdc.MustMarshalBinaryBare(msg))
			ps.hasEntropyShare(ps.lastComputedEntropyHeight + 1, key, numValidators)
			if count + 1 >= threshold {
				ps.entropyComputed(ps.lastComputedEntropyHeight + 1)
			}
			return true
		}
	}
	return false
}

func (ps *PeerState) HasEntropyShare(height int64, index int, numValidators int) {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	ps.hasEntropyShare(height, index, numValidators)
}

func (ps *PeerState) hasEntropyShare(height int64, index int, numValidators int) {
	if index < 0 {
		return
	}

	// Make sure bit array is initialised
	if ps.entropyShares[height] == nil {
		ps.entropyShares[height] = bits.NewBitArray(numValidators)
	}

	ps.entropyShares[height].SetIndex(index, true)
}

func (ps *PeerState) entropyComputed(height int64) {
	delete(ps.entropyShares, height)
	ps.lastComputedEntropyHeight++
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

func RegisterMessages(cdc *amino.Codec) {
	cdc.RegisterInterface((*Message)(nil), nil)
	cdc.RegisterConcrete(&HasEntropyShareMessage{}, "tendermint/HasEntropyShare", nil)
	cdc.RegisterConcrete(&EntropyShareMessage{}, "tendermint/EntropyShare", nil)
}

func decodeMsg(bz []byte) (msg Message, err error) {
	if len(bz) > maxMsgSize {
		return msg, fmt.Errorf("msg exceeds max size (%d > %d)", len(bz), maxMsgSize)
	}
	err = cdc.UnmarshalBinaryBare(bz, &msg)
	return
}

//-------------------------------------

// EntropyShareMessage is for computing DRB
type HasEntropyShareMessage struct {
	Height int64
	SignerAddress crypto.Address
}

// ValidateBasic performs basic validation.
func (m *HasEntropyShareMessage) ValidateBasic() error {
	if m.Height < GenesisHeight + 1{
		return errors.New("invalid Height")
	}

	if len(m.SignerAddress) != crypto.AddressSize {
		return fmt.Errorf("expected ValidatorAddress size to be %d bytes, got %d bytes",
			crypto.AddressSize,
			len(m.SignerAddress),
		)
	}
	return nil
}

// String returns a string representation.
func (m *HasEntropyShareMessage) String() string {
	return fmt.Sprintf("[HESM %v %v]", m.Height, m.SignerAddress)
}

//-------------------------------------

// EntropyShareMessage is for computing DRB
type EntropyShareMessage struct {
	*EntropyShare
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
