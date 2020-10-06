package types

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	amino "github.com/tendermint/go-amino"

	"github.com/tendermint/tendermint/crypto"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmproto "github.com/tendermint/tendermint/proto/types"
)

const (
	// MaxEvidenceBytes is a maximum size of any evidence (including amino overhead).
	MaxEvidenceBytes int64 = 484
)

// ErrEvidenceInvalid wraps a piece of evidence and the error denoting how or why it is invalid.
type ErrEvidenceInvalid struct {
	Evidence   Evidence
	ErrorValue error
}

// NewErrEvidenceInvalid returns a new EvidenceInvalid with the given err.
func NewErrEvidenceInvalid(ev Evidence, err error) *ErrEvidenceInvalid {
	return &ErrEvidenceInvalid{ev, err}
}

// Error returns a string representation of the error.
func (err *ErrEvidenceInvalid) Error() string {
	return fmt.Sprintf("Invalid evidence: %v. Evidence: %v", err.ErrorValue, err.Evidence)
}

// ErrEvidenceOverflow is for when there is too much evidence in a block.
type ErrEvidenceOverflow struct {
	MaxNum int64
	GotNum int64
}

// NewErrEvidenceOverflow returns a new ErrEvidenceOverflow where got > max.
func NewErrEvidenceOverflow(max, got int64) *ErrEvidenceOverflow {
	return &ErrEvidenceOverflow{max, got}
}

// Error returns a string representation of the error.
func (err *ErrEvidenceOverflow) Error() string {
	return fmt.Sprintf("Too much evidence: Max %d, got %d", err.MaxNum, err.GotNum)
}

//-------------------------------------------

// Evidence represents any provable malicious activity by a validator
type Evidence interface {
	Height() int64                                     // height of the equivocation
	ValidatorHeight() int64                            // height of validators
	Time() time.Time                                   // time of the equivocation
	Address() []byte                                   // address of the equivocating validator
	Bytes() []byte                                     // bytes which comprise the evidence
	Hash() []byte                                      // hash of the evidence
	Verify(chainID string, pubKey crypto.PubKey) error // verify the evidence
	Equal(Evidence) bool                               // check equality of evidence

	ValidateBasic() error
	String() string

	SignBytes(chainID string) []byte // for signing: evidence as bytes with chainID appended
}

func EvidenceToProto(evidence Evidence) (*tmproto.Evidence, error) {
	if evidence == nil {
		return nil, errors.New("nil evidence")
	}

	switch evi := evidence.(type) {
	case *DuplicateVoteEvidence:
		voteB := evi.VoteB.ToProto()
		voteA := evi.VoteA.ToProto()
		pk, err := cryptoenc.PubKeyToProto(evi.PubKey)
		if err != nil {
			return nil, err
		}
		tp := &tmproto.Evidence{
			Sum: &tmproto.Evidence_DuplicateVoteEvidence{
				DuplicateVoteEvidence: &tmproto.DuplicateVoteEvidence{
					PubKey: &pk,
					VoteA:  voteA,
					VoteB:  voteB,
				},
			},
		}
		return tp, nil
	case MockEvidence:
		if err := evi.ValidateBasic(); err != nil {
			return nil, err
		}

		tp := &tmproto.Evidence{
			Sum: &tmproto.Evidence_MockEvidence{
				MockEvidence: &tmproto.MockEvidence{
					EvidenceHeight:  evi.Height(),
					EvidenceTime:    evi.Time(),
					EvidenceAddress: evi.Address(),
				},
			},
		}

		return tp, nil
	case MockRandomEvidence:
		if err := evi.ValidateBasic(); err != nil {
			return nil, err
		}

		tp := &tmproto.Evidence{
			Sum: &tmproto.Evidence_MockRandomEvidence{
				MockRandomEvidence: &tmproto.MockRandomEvidence{
					EvidenceHeight:  evi.Height(),
					EvidenceTime:    evi.Time(),
					EvidenceAddress: evi.Address(),
					RandBytes:       evi.randBytes,
				},
			},
		}
		return tp, nil
	case *BeaconInactivityEvidence:
		if err := evi.ValidateBasic(); err != nil {
			return nil, err
		}

		tp := &tmproto.Evidence{
			Sum: &tmproto.Evidence_BeaconInactivityEvidence{
				BeaconInactivityEvidence: &tmproto.BeaconInactivityEvidence{
					EvidenceHeight:       evi.Height(),
					EvidenceTime:         evi.Time(),
					DefendantAddress:     evi.DefendantAddress,
					ComplainantAddress:   evi.ComplainantAddress,
					AeonStart:            evi.AeonStart,
					ComplainantSignature: evi.ComplainantSignature,
				},
			},
		}
		return tp, nil
	default:
		return nil, fmt.Errorf("toproto: evidence is not recognized: %T", evi)
	}
}

func EvidenceFromProto(evidence *tmproto.Evidence) (Evidence, error) {
	if evidence == nil {
		return nil, errors.New("nil evidence")
	}

	switch evi := evidence.Sum.(type) {
	case *tmproto.Evidence_DuplicateVoteEvidence:

		vA, err := VoteFromProto(evi.DuplicateVoteEvidence.VoteA)
		if err != nil {
			return nil, err
		}

		vB, err := VoteFromProto(evi.DuplicateVoteEvidence.VoteB)
		if err != nil {
			return nil, err
		}

		pk, err := cryptoenc.PubKeyFromProto(evi.DuplicateVoteEvidence.GetPubKey())
		if err != nil {
			return nil, err
		}

		dve := DuplicateVoteEvidence{
			PubKey: pk,
			VoteA:  vA,
			VoteB:  vB,
		}

		return &dve, dve.ValidateBasic()
	case *tmproto.Evidence_MockEvidence:
		me := MockEvidence{
			EvidenceHeight:  evi.MockEvidence.GetEvidenceHeight(),
			EvidenceAddress: evi.MockEvidence.GetEvidenceAddress(),
			EvidenceTime:    evi.MockEvidence.GetEvidenceTime(),
		}
		return me, me.ValidateBasic()
	case *tmproto.Evidence_MockRandomEvidence:
		mre := MockRandomEvidence{
			MockEvidence: MockEvidence{
				EvidenceHeight:  evi.MockRandomEvidence.GetEvidenceHeight(),
				EvidenceAddress: evi.MockRandomEvidence.GetEvidenceAddress(),
				EvidenceTime:    evi.MockRandomEvidence.GetEvidenceTime(),
			},
			randBytes: evi.MockRandomEvidence.RandBytes,
		}
		return mre, mre.ValidateBasic()
	case *tmproto.Evidence_BeaconInactivityEvidence:
		bie := BeaconInactivityEvidence{
			CreationHeight:       evi.BeaconInactivityEvidence.GetEvidenceHeight(),
			CreationTime:         evi.BeaconInactivityEvidence.GetEvidenceTime(),
			DefendantAddress:     evi.BeaconInactivityEvidence.GetDefendantAddress(),
			ComplainantAddress:   evi.BeaconInactivityEvidence.GetComplainantAddress(),
			AeonStart:            evi.BeaconInactivityEvidence.GetAeonStart(),
			ComplainantSignature: evi.BeaconInactivityEvidence.GetComplainantSignature(),
		}
		return &bie, bie.ValidateBasic()
	default:
		return nil, errors.New("evidence is not recognized")
	}
}

func RegisterEvidences(cdc *amino.Codec) {
	cdc.RegisterInterface((*Evidence)(nil), nil)
	cdc.RegisterConcrete(&DuplicateVoteEvidence{}, "tendermint/DuplicateVoteEvidence", nil)
	cdc.RegisterConcrete(&BeaconInactivityEvidence{}, "tendermint/BeaconInactivityEvidence", nil)
}

func RegisterMockEvidences(cdc *amino.Codec) {
	cdc.RegisterConcrete(MockEvidence{}, "tendermint/MockEvidence", nil)
	cdc.RegisterConcrete(MockRandomEvidence{}, "tendermint/MockRandomEvidence", nil)
}

const (
	MaxEvidenceBytesDenominator = 10
)

// MaxEvidencePerBlock returns the maximum number of evidences
// allowed in the block and their maximum total size (limitted to 1/10th
// of the maximum block size).
// TODO: change to a constant, or to a fraction of the validator set size.
// See https://github.com/tendermint/tendermint/issues/2590
func MaxEvidencePerBlock(blockMaxBytes int64) (int64, int64) {
	maxBytes := blockMaxBytes / MaxEvidenceBytesDenominator
	maxNum := maxBytes / MaxEvidenceBytes
	return maxNum, maxBytes
}

//-------------------------------------------

// DuplicateVoteEvidence contains evidence a validator signed two conflicting
// votes.
type DuplicateVoteEvidence struct {
	PubKey crypto.PubKey
	VoteA  *Vote
	VoteB  *Vote
}

var _ Evidence = &DuplicateVoteEvidence{}

// NewDuplicateVoteEvidence creates DuplicateVoteEvidence with right ordering given
// two conflicting votes. If one of the votes is nil, evidence returned is nil as well
func NewDuplicateVoteEvidence(pubkey crypto.PubKey, vote1 *Vote, vote2 *Vote) *DuplicateVoteEvidence {
	var voteA, voteB *Vote
	if vote1 == nil || vote2 == nil {
		return nil
	}
	if strings.Compare(vote1.BlockID.Key(), vote2.BlockID.Key()) == -1 {
		voteA = vote1
		voteB = vote2
	} else {
		voteA = vote2
		voteB = vote1
	}
	return &DuplicateVoteEvidence{
		PubKey: pubkey,
		VoteA:  voteA,
		VoteB:  voteB,
	}
}

// String returns a string representation of the evidence.
func (dve *DuplicateVoteEvidence) String() string {
	return fmt.Sprintf("VoteA: %v; VoteB: %v", dve.VoteA, dve.VoteB)

}

// Height returns the height this evidence refers to.
func (dve *DuplicateVoteEvidence) Height() int64 {
	return dve.VoteA.Height
}

// Height returns the height this evidence refers to.
func (dve *DuplicateVoteEvidence) ValidatorHeight() int64 {
	return dve.VoteA.Height
}

// Time return the time the evidence was created
func (dve *DuplicateVoteEvidence) Time() time.Time {
	return dve.VoteA.Timestamp
}

// Address returns the address of the validator.
func (dve *DuplicateVoteEvidence) Address() []byte {
	return dve.PubKey.Address()
}

// Hash returns the hash of the evidence.
func (dve *DuplicateVoteEvidence) Bytes() []byte {
	return cdcEncode(dve)
}

// Hash returns the hash of the evidence.
func (dve *DuplicateVoteEvidence) Hash() []byte {
	return tmhash.Sum(cdcEncode(dve))
}

// Verify returns an error if the two votes aren't conflicting.
// To be conflicting, they must be from the same validator, for the same H/R/S, but for different blocks.
func (dve *DuplicateVoteEvidence) Verify(chainID string, pubKey crypto.PubKey) error {
	// H/R/S must be the same
	if dve.VoteA.Height != dve.VoteB.Height ||
		dve.VoteA.Round != dve.VoteB.Round ||
		dve.VoteA.Type != dve.VoteB.Type {
		return fmt.Errorf("duplicateVoteEvidence Error: H/R/S does not match. Got %v and %v", dve.VoteA, dve.VoteB)
	}

	// Address must be the same
	if !bytes.Equal(dve.VoteA.ValidatorAddress, dve.VoteB.ValidatorAddress) {
		return fmt.Errorf(
			"duplicateVoteEvidence Error: Validator addresses do not match. Got %X and %X",
			dve.VoteA.ValidatorAddress,
			dve.VoteB.ValidatorAddress,
		)
	}

	// Index must be the same
	if dve.VoteA.ValidatorIndex != dve.VoteB.ValidatorIndex {
		return fmt.Errorf(
			"duplicateVoteEvidence Error: Validator indices do not match. Got %d and %d",
			dve.VoteA.ValidatorIndex,
			dve.VoteB.ValidatorIndex,
		)
	}

	// BlockIDs must be different
	if dve.VoteA.BlockID.Equals(dve.VoteB.BlockID) {
		return fmt.Errorf(
			"duplicateVoteEvidence Error: BlockIDs are the same (%v) - not a real duplicate vote",
			dve.VoteA.BlockID,
		)
	}

	// pubkey must match address (this should already be true, sanity check)
	addr := dve.VoteA.ValidatorAddress
	if !bytes.Equal(pubKey.Address(), addr) {
		return fmt.Errorf("duplicateVoteEvidence FAILED SANITY CHECK - address (%X) doesn't match pubkey (%v - %X)",
			addr, pubKey, pubKey.Address())
	}

	// Signatures must be valid
	if !pubKey.VerifyBytes(dve.VoteA.SignBytes(chainID), dve.VoteA.Signature) {
		return fmt.Errorf("duplicateVoteEvidence Error verifying VoteA: %v", ErrVoteInvalidSignature)
	}
	if !pubKey.VerifyBytes(dve.VoteB.SignBytes(chainID), dve.VoteB.Signature) {
		return fmt.Errorf("duplicateVoteEvidence Error verifying VoteB: %v", ErrVoteInvalidSignature)
	}

	return nil
}

// Equal checks if two pieces of evidence are equal.
func (dve *DuplicateVoteEvidence) Equal(ev Evidence) bool {
	if _, ok := ev.(*DuplicateVoteEvidence); !ok {
		return false
	}

	// just check their hashes
	dveHash := tmhash.Sum(cdcEncode(dve))
	evHash := tmhash.Sum(cdcEncode(ev))
	fmt.Println(dveHash, evHash)
	return bytes.Equal(dveHash, evHash)
}

// ValidateBasic performs basic validation.
func (dve *DuplicateVoteEvidence) ValidateBasic() error {
	if len(dve.PubKey.Bytes()) == 0 {
		return errors.New("empty PubKey")
	}
	if dve.VoteA == nil || dve.VoteB == nil {
		return fmt.Errorf("one or both of the votes are empty %v, %v", dve.VoteA, dve.VoteB)
	}
	if err := dve.VoteA.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid VoteA: %v", err)
	}
	if err := dve.VoteB.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid VoteB: %v", err)
	}
	// Enforce Votes are lexicographically sorted on blockID
	if strings.Compare(dve.VoteA.BlockID.Key(), dve.VoteB.BlockID.Key()) >= 0 {
		return errors.New("duplicate votes in invalid order")
	}
	return nil
}

// Returns evidence as bytes with chainID appended
func (dve *DuplicateVoteEvidence) SignBytes(chainID string) []byte {
	bz, err := cdc.MarshalBinaryLengthPrefixed(dve)
	if err != nil {
		panic(err)
	}
	return append([]byte(chainID), bz...)
}

//-----------------------------------------------------------------

// UNSTABLE
type MockRandomEvidence struct {
	MockEvidence
	randBytes []byte
}

var _ Evidence = &MockRandomEvidence{}

// UNSTABLE
func NewMockRandomEvidence(height int64, eTime time.Time, address []byte, randBytes []byte) MockRandomEvidence {
	return MockRandomEvidence{
		MockEvidence{
			EvidenceHeight:  height,
			EvidenceTime:    eTime,
			EvidenceAddress: address}, randBytes,
	}
}

func (e MockRandomEvidence) Hash() []byte {
	return []byte(fmt.Sprintf("%d-%x", e.EvidenceHeight, e.randBytes))
}

// UNSTABLE
type MockEvidence struct {
	EvidenceHeight  int64
	EvidenceTime    time.Time
	EvidenceAddress []byte
}

var _ Evidence = &MockEvidence{}

// UNSTABLE
func NewMockEvidence(height int64, eTime time.Time, idx int, address []byte) MockEvidence {
	return MockEvidence{
		EvidenceHeight:  height,
		EvidenceTime:    eTime,
		EvidenceAddress: address}
}

func (e MockEvidence) Height() int64          { return e.EvidenceHeight }
func (e MockEvidence) ValidatorHeight() int64 { return e.EvidenceHeight }
func (e MockEvidence) Time() time.Time        { return e.EvidenceTime }
func (e MockEvidence) Address() []byte        { return e.EvidenceAddress }
func (e MockEvidence) Hash() []byte {
	return []byte(fmt.Sprintf("%d-%x-%s",
		e.EvidenceHeight, e.EvidenceAddress, e.EvidenceTime))
}
func (e MockEvidence) Bytes() []byte {
	return []byte(fmt.Sprintf("%d-%x-%s",
		e.EvidenceHeight, e.EvidenceAddress, e.EvidenceTime))
}
func (e MockEvidence) Verify(chainID string, pubKey crypto.PubKey) error { return nil }
func (e MockEvidence) Equal(ev Evidence) bool {
	e2 := ev.(MockEvidence)
	return e.EvidenceHeight == e2.EvidenceHeight &&
		bytes.Equal(e.EvidenceAddress, e2.EvidenceAddress)
}
func (e MockEvidence) ValidateBasic() error { return nil }
func (e MockEvidence) String() string {
	return fmt.Sprintf("Evidence: %d/%s/%s", e.EvidenceHeight, e.Time(), e.EvidenceAddress)
}
func (e MockEvidence) SignBytes(chainID string) []byte {
	bz, err := cdc.MarshalBinaryLengthPrefixed(e)
	if err != nil {
		panic(err)
	}
	return append([]byte(chainID), bz...)
}

//-------------------------------------------

// BeaconInactivityEvidence contains evidence a validator was did not
type BeaconInactivityEvidence struct {
	CreationHeight       int64          // Height evidence was created
	CreationTime         time.Time      // Time evidence was created
	DefendantAddress     crypto.Address // Address of validator accused of inactivity
	ComplainantAddress   crypto.Address // Address of validator submitting complaint complaint
	AeonStart            int64          // Height for fetching validators
	ComplainantSignature []byte
}

var _ Evidence = &BeaconInactivityEvidence{}

// NewBeaconInactivityEvidence creates BeaconInactivityEvidence
func NewBeaconInactivityEvidence(height int64, defAddress crypto.Address, comAddress crypto.Address, aeon int64) *BeaconInactivityEvidence {
	return &BeaconInactivityEvidence{
		CreationHeight:     height,
		CreationTime:       time.Now(),
		DefendantAddress:   defAddress,
		ComplainantAddress: comAddress,
		AeonStart:          aeon,
	}
}

// String returns a string representation of the evidence.
func (bie *BeaconInactivityEvidence) String() string {
	return fmt.Sprintf("DefendantPubKey: %s, ComplainantPubKey: %s, Aeon: %v", bie.DefendantAddress,
		bie.ComplainantAddress, bie.AeonStart)

}

// Height returns evidence was created
func (bie *BeaconInactivityEvidence) Height() int64 {
	return bie.CreationHeight
}

// Height returns validator height
func (bie *BeaconInactivityEvidence) ValidatorHeight() int64 {
	return bie.AeonStart
}

// Time return
func (bie *BeaconInactivityEvidence) Time() time.Time {
	return bie.CreationTime
}

// Address returns the address of the validator.
func (bie *BeaconInactivityEvidence) Address() []byte {
	return bie.ComplainantAddress
}

// Bytes returns the evidence as byte slice
func (bie *BeaconInactivityEvidence) Bytes() []byte {
	return cdcEncode(bie)
}

// Hash returns the hash of the evidence.
func (bie *BeaconInactivityEvidence) Hash() []byte {
	return tmhash.Sum(cdcEncode(bie))
}

// Verify returns the signature attached to the evidence matches the complainant address
func (bie *BeaconInactivityEvidence) Verify(chainID string, complainantPubKey crypto.PubKey) error {
	if !complainantPubKey.VerifyBytes(bie.SignBytes(chainID), bie.ComplainantSignature) {
		return fmt.Errorf("ComplainantSignature invalid")
	}

	// Need to verify defendant address in state and also aeon start is correct
	// and evidence height is greater than aeon start

	return nil
}

// For signing with private key
func (bie BeaconInactivityEvidence) SignBytes(chainID string) []byte {
	bie.ComplainantSignature = nil
	bz, err := cdc.MarshalBinaryLengthPrefixed(bie)
	if err != nil {
		panic(err)
	}
	return append([]byte(chainID), bz...)
}

// Equal checks if two pieces of evidence are equal.
func (bie *BeaconInactivityEvidence) Equal(ev Evidence) bool {
	if _, ok := ev.(*BeaconInactivityEvidence); !ok {
		return false
	}

	// just check their hashes
	bieHash := tmhash.Sum(cdcEncode(bie))
	evHash := tmhash.Sum(cdcEncode(ev))
	return bytes.Equal(bieHash, evHash)
}

// ValidateBasic performs basic validation.
func (bie *BeaconInactivityEvidence) ValidateBasic() error {
	if len(bie.ComplainantAddress) == 0 {
		return errors.New("empty ComplainantAddress")
	}
	if len(bie.DefendantAddress) == 0 {
		return errors.New("empty DefendantAddress")
	}
	if bie.AeonStart <= 0 {
		return errors.New("invalid aeon start")
	}
	if len(bie.ComplainantSignature) == 0 {
		return errors.New("empty complainant signature")
	}
	return nil
}

//-------------------------------------------

// EvidenceList is a list of Evidence. Evidences is not a word.
type EvidenceList []Evidence

// Hash returns the simple merkle root hash of the EvidenceList.
func (evl EvidenceList) Hash() []byte {
	// These allocations are required because Evidence is not of type Bytes, and
	// golang slices can't be typed cast. This shouldn't be a performance problem since
	// the Evidence size is capped.
	evidenceBzs := make([][]byte, len(evl))
	for i := 0; i < len(evl); i++ {
		evidenceBzs[i] = evl[i].Bytes()
	}
	return merkle.SimpleHashFromByteSlices(evidenceBzs)
}

func (evl EvidenceList) String() string {
	s := ""
	for _, e := range evl {
		s += fmt.Sprintf("%s\t\t", e)
	}
	return s
}

// Has returns true if the evidence is in the EvidenceList.
func (evl EvidenceList) Has(evidence Evidence) bool {
	for _, ev := range evl {
		if ev.Equal(evidence) {
			return true
		}
	}
	return false
}
