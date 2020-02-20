package beacon

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/libs/bits"
	tmevents "github.com/tendermint/tendermint/libs/events"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
)

const (
	StateChannel   = byte(0x80)
	EntropyChannel = byte(0x81)

	maxMsgSize = 1048576 // 1MB; NOTE/TODO: keep in sync with types.PartSet sizes.

	PeerGossipSleepDuration     = 100 * time.Millisecond
	ComputeEntropySleepDuration = 100 * time.Millisecond
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
func NewReactor(entropyGenerator *EntropyGenerator, fastSync bool, options ...ReactorOption) *Reactor {
	conR := &Reactor{
		entropyGen: entropyGenerator,
		fastSync:   fastSync,
	}
	conR.BaseReactor = *p2p.NewBaseReactor("Reactor", conR)

	for _, option := range options {
		option(conR)
	}

	return conR
}

// OnStart implements BaseService by subscribing to events, which later will be
// broadcasted to other peers and starting state if we're not in fast sync.
func (beaconR *Reactor) OnStart() error {
	beaconR.Logger.Info("Reactor ")

	beaconR.subscribeToBroadcastEvents()

	if !beaconR.fastSync {
		return beaconR.entropyGen.Start()
	}

	return nil
}

// OnStop implements BaseService by unsubscribing from events and stopping
// state.
func (beaconR *Reactor) OnStop() {
	beaconR.unsubscribeFromBroadcastEvents()
	beaconR.entropyGen.Stop()
}

// Switch from fast sync, when no entropy is generated, to consensus mode by resetting the
// last computed entropy
func (beaconR *Reactor) SwitchToConsensus(state sm.State) {
	beaconR.Logger.Info("SwitchToConsensus")
	beaconR.entropyGen.SetLastComputedEntropy(types.ComputedEntropy{Height: state.LastBlockHeight, GroupSignature: state.LastComputedEntropy})

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
	// TODO
	// ps, ok := peer.Get(BeaconPeerStateKey).(*PeerState)
	// if !ok {
	// 	panic(fmt.Sprintf("Peer %v has no state", peer))
	// }
	// ps.Disconnect()
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
		case *HasEntropyShareMessage:
			if beaconR.entropyGen != nil {
				index, _ := beaconR.entropyGen.Validators.GetByAddress(msg.SignerAddress)
				ps.HasEntropyShare(msg.Height, index, beaconR.entropyGen.Validators.Size())
			} else {
				panic(fmt.Sprintf("BeaconReactor has no EntropyGenerator"))
			}
		default:
			beaconR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
		}

	case EntropyChannel:
		switch msg := msg.(type) {
		case *EntropyShareMessage:
			if beaconR.entropyGen != nil {
				beaconR.entropyGen.ApplyEntropyShare(msg.EntropyShare)
			} else {
				panic(fmt.Sprintf("BeaconReactor has no EntropyGenerator"))
			}
		default:
			beaconR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
		}

	default:
		beaconR.Logger.Error(fmt.Sprintf("Unknown chId %X", chID))
	}
}

//--------------------------------------

// subscribeToBroadcastEvents subscribes for has entropy share messages
func (beaconR *Reactor) subscribeToBroadcastEvents() {
	const subscriber = "beacon-reactor"
	beaconR.entropyGen.evsw.AddListenerForEvent(subscriber, types.EventEntropyShare,
		func(data tmevents.EventData) {
			beaconR.broadcastHasEntropyShareMessage(data.(*types.EntropyShare))
		})
}

func (beaconR *Reactor) unsubscribeFromBroadcastEvents() {
	const subscriber = "beacon-reactor"
	beaconR.entropyGen.evsw.RemoveListener(subscriber)
}

func (beaconR *Reactor) broadcastHasEntropyShareMessage(es *types.EntropyShare) {
	esMsg := &HasEntropyShareMessage{
		Height:        es.Height,
		SignerAddress: es.SignerAddress,
	}
	beaconR.Switch.Broadcast(StateChannel, cdc.MustMarshalBinaryBare(esMsg))
}

func (beaconR *Reactor) gossipEntropySharesRoutine(peer p2p.Peer, ps *PeerState) {
	logger := beaconR.Logger.With("peer", peer)

OUTER_LOOP:
	for {
		// Manage disconnects from self or peer.
		if !peer.IsRunning() || !beaconR.IsRunning() {
			logger.Info("Stopping gossipEntropySharesRoutine for peer")
			return
		}

		if beaconR.entropyGen != nil {
			peerLastEntropyHeight := ps.GetLastComputedEntropyHeight()
			if ps.PickSendEntropyShare(
				beaconR.entropyGen.GetEntropyShares(peerLastEntropyHeight+1),
				beaconR.entropyGen.Validators.Size()) {
				logger.Debug("PickSendEntropyShare successful", "height", peerLastEntropyHeight+1)
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
func (beaconR *Reactor) String() string {
	// better not to access shared variables
	return "EntropyReactor" // conR.StringIndented("")
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
	entropyShares             map[int64]*bits.BitArray
	lastComputedEntropyHeight int64
}

// NewPeerState returns a new PeerState for the given Peer
func NewPeerState(peer p2p.Peer) *PeerState {
	return &PeerState{
		peer:                      peer,
		logger:                    log.NewNopLogger(),
		entropyShares:             make(map[int64]*bits.BitArray),
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

func (ps *PeerState) PickSendEntropyShare(entropyShares map[int]types.EntropyShare, numValidators int) bool {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	if entropyShares == nil {
		return false
	}
	if len(entropyShares) == 0 {
		return false
	}

	peerEntropyShares := ps.entropyShares[ps.lastComputedEntropyHeight+1]

	for key, value := range entropyShares {
		if !peerEntropyShares.GetIndex(key) {
			msg := &EntropyShareMessage{&value}
			ps.peer.Send(EntropyChannel, cdc.MustMarshalBinaryBare(msg))
			ps.hasEntropyShare(ps.lastComputedEntropyHeight+1, key, numValidators)
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

	// Check if peer has received enough to compute entropy
	count := 0
	for i := 0; i < numValidators; i++ {
		if ps.entropyShares[height].GetIndex(i) {
			count++
		}
	}
	threshold := numValidators/2 + 1
	if count >= threshold {
		ps.entropyComputed(height)
	}
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

// HasEntropyShareMessage is for computing DRB
type HasEntropyShareMessage struct {
	Height        int64
	SignerAddress crypto.Address
}

// ValidateBasic performs basic validation.
func (m *HasEntropyShareMessage) ValidateBasic() error {
	if m.Height < types.GenesisHeight+1 {
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
