package beacon

import (
	"testing"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/tx_extensions"

	"github.com/stretchr/testify/assert"

	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/types"
)

// Set up a DKG and add it to a slot protocol for tests
func SlotProtocolSetup() (sp *SlotProtocolEnforcer, dkg *DistributedKeyGeneration) {
	sp = NewSlotProtocolEnforcer()
	dkg = exampleDKG(4)
	sp.UpdateDKG(dkg)

	return
}

// Create a random Tx, the slot protocol should allow this
func TestSlotProtocolAllowsNormal(t *testing.T) {

	sp, _ := SlotProtocolSetup()
	assert.True(t, sp.ShouldAdd([]byte("abc"), 0, p2p.ID("0"), nil))
}

// Create a valid dkg message, this should be allowed, one time only
func TestSlotProtocolAllowsDKGOneTimeOnly(t *testing.T) {

	sp, dkg := SlotProtocolSetup()

	msg := dkg.newDKGMessage(types.DKGDryRun, "data", nil)

	msgAsBytes := tx_extensions.AsBytes(msg)

	assert.True(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))
	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))
}

// Create an invalid dkg message, this should not be allowed
func TestSlotProtocolRejectsInvalid(t *testing.T) {

	sp, dkg := SlotProtocolSetup()

	msg := dkg.newDKGMessage(types.DKGDryRun, "data", nil)
	msg.Type = 999

	msgAsBytes := tx_extensions.AsBytes(msg)

	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))
}

// Check that dkg messages that are too far in the future or too old
// are rejected
func TestSlotProtocolAllowsNormalOneTimeOnlyxxy(t *testing.T) {

	sp, dkg := SlotProtocolSetup()

	// Iteration is too far ahead
	msg := dkg.newDKGMessage(types.DKGDryRun, "data", nil)
	msg.DKGIteration = msg.DKGIteration + 2

	msgAsBytes := tx_extensions.AsBytes(msg)
	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))

	// Iteration is too far behind
	msg = dkg.newDKGMessage(types.DKGDryRun, "data", nil)
	msg.DKGIteration = msg.DKGIteration - 1

	msgAsBytes = tx_extensions.AsBytes(msg)
	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))

	// ID is too far ahead
	msg = dkg.newDKGMessage(types.DKGDryRun, "data", nil)
	msg.DKGID = msg.DKGID + 2

	msgAsBytes = tx_extensions.AsBytes(msg)
	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))

	// ID is too far behind
	msg = dkg.newDKGMessage(types.DKGDryRun, "data", nil)
	msg.DKGID = msg.DKGID - 1

	msgAsBytes = tx_extensions.AsBytes(msg)
	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))
}

// Check that messages that are slightly too early are rejected, but will still be checked/added later
func TestSlotProtocolAllowsNormalOneTimeOnlyxxybb(t *testing.T) {
	sp, dkg := SlotProtocolSetup()

	// Iteration is slightly too early
	msg := dkg.newDKGMessage(types.DKGDryRun, "data", nil)
	msg.DKGIteration = msg.DKGIteration + 1

	msgAsBytes := tx_extensions.AsBytes(msg)
	assert.False(t, sp.ShouldAdd(msgAsBytes, 0, p2p.ID("0"), nil))

	callbackTriggered := false

	cb := func([]byte, uint16, p2p.ID, *abci.Response) {
		callbackTriggered = true
	}

	sp.SetCbWhenUpdated(cb)

	// Doesn't matter that we update with the same dkg - messages should
	// always be rechecked (callback triggered)
	sp.UpdateDKG(dkg)

	assert.True(t, callbackTriggered)
}
