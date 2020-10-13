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
	Height() int64          // height of the equivocation
	ValidatorHeight() int64 // height of validators
	Time() time.Time        // time of the equivocation
	Address() []byte        // address of the equivocating validator
	Bytes() []byte          // bytes which comprise the evidence
	Hash() []byte           // hash of the evidence
	Equal(Evidence) bool    // check equality of evidence

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
					Threshold:            evi.Threshold,
				},
			},
		}
		return tp, nil
	case *DKGEvidence:
		if err := evi.ValidateBasic(); err != nil {
			return nil, err
		}

		tp := &tmproto.Evidence{
			Sum: &tmproto.Evidence_DkgEvidence{
				DkgEvidence: &tmproto.DKGEvidence{
					EvidenceHeight:       evi.Height(),
					EvidenceTime:         evi.Time(),
					DefendantAddress:     evi.DefendantAddress,
					ComplainantAddress:   evi.ComplainantAddress,
					ValidatorHeight:      evi.ValHeight,
					DkgId:                evi.DKGID,
					DkgIteration:         evi.DKGIteration,
					Threshold:            evi.Threshold,
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
			Threshold:            evi.BeaconInactivityEvidence.GetThreshold(),
			ComplainantSignature: evi.BeaconInactivityEvidence.GetComplainantSignature(),
		}
		return &bie, bie.ValidateBasic()
	case *tmproto.Evidence_DkgEvidence:
		de := DKGEvidence{
			CreationHeight:       evi.DkgEvidence.GetEvidenceHeight(),
			CreationTime:         evi.DkgEvidence.GetEvidenceTime(),
			DefendantAddress:     evi.DkgEvidence.GetDefendantAddress(),
			ComplainantAddress:   evi.DkgEvidence.GetComplainantAddress(),
			ValHeight:            evi.DkgEvidence.GetValidatorHeight(),
			DKGID:                evi.DkgEvidence.GetDkgId(),
			DKGIteration:         evi.DkgEvidence.GetDkgIteration(),
			Threshold:            evi.DkgEvidence.GetThreshold(),
			ComplainantSignature: evi.DkgEvidence.GetComplainantSignature(),
		}
		return &de, de.ValidateBasic()
	default:
		return nil, errors.New("evidence is not recognized")
	}
}

func RegisterEvidences(cdc *amino.Codec) {
	cdc.RegisterInterface((*Evidence)(nil), nil)
	cdc.RegisterConcrete(&DuplicateVoteEvidence{}, "tendermint/DuplicateVoteEvidence", nil)
	cdc.RegisterConcrete(&BeaconInactivityEvidence{}, "tendermint/BeaconInactivityEvidence", nil)
	cdc.RegisterConcrete(&DKGEvidence{}, "tendermint/DKGEvidence", nil)
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

// BeaconInactivityEvidence contains evidence a validator was not sufficiently active
// in the random beacon
type BeaconInactivityEvidence struct {
	CreationHeight       int64          // Height evidence was created
	CreationTime         time.Time      // Time evidence was created
	DefendantAddress     crypto.Address // Address of validator accused of inactivity
	ComplainantAddress   crypto.Address // Address of validator submitting complaint complaint
	AeonStart            int64          // Height for fetching validators
	Threshold            int64          // Threshold of complaints for slashing (depends on validator size)
	ComplainantSignature []byte
}

var _ Evidence = &BeaconInactivityEvidence{}

// NewBeaconInactivityEvidence creates BeaconInactivityEvidence
func NewBeaconInactivityEvidence(height int64, defAddress crypto.Address, comAddress crypto.Address, aeon int64, threshold int64) *BeaconInactivityEvidence {
	return &BeaconInactivityEvidence{
		CreationHeight:     height,
		CreationTime:       time.Now(),
		DefendantAddress:   defAddress,
		ComplainantAddress: comAddress,
		AeonStart:          aeon,
		Threshold:          threshold,
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

// ValidatorHeight returns validator height. Validators running DRB at aeon start
// correspond to the DKG validators at aeon start -1
func (bie *BeaconInactivityEvidence) ValidatorHeight() int64 {
	return bie.AeonStart - 1
}

// Time return
func (bie *BeaconInactivityEvidence) Time() time.Time {
	return bie.CreationTime
}

// Address returns the address of the validator.
func (bie *BeaconInactivityEvidence) Address() []byte {
	return bie.DefendantAddress
}

// Bytes returns the evidence as byte slice
func (bie *BeaconInactivityEvidence) Bytes() []byte {
	return cdcEncode(bie)
}

// Hash returns the hash of the unique fields in evidence. Prevents submission
// of multiple evidence by using a different creation time or signature
func (bie *BeaconInactivityEvidence) Hash() []byte {
	uniqueInfo := struct {
		AeonStart          int64
		DefendantAddress   []byte
		ComplainantAddress []byte
		Threshold          int64
	}{bie.AeonStart, bie.DefendantAddress, bie.ComplainantAddress, bie.Threshold}
	return tmhash.Sum(cdcEncode(uniqueInfo))
}

// Verify validates information contained in Evidence. Ensures signature verifies with complainant address, valid aeon start and
// that the evidence was created after the aeon start
func (bie *BeaconInactivityEvidence) Verify(chainID string, blockEntropy BlockEntropy, valset *ValidatorSet,
	params EntropyParams) error {
	// Check aeon start is correct
	if blockEntropy.NextAeonStart != bie.AeonStart {
		return fmt.Errorf("incorrect aeon start. Got %v, expected %v", bie.ValidatorHeight(), blockEntropy.NextAeonStart)
	}
	// Creation height of evidence needs to be during the entropy generation aeon
	if bie.CreationHeight <= bie.AeonStart || bie.CreationHeight > bie.AeonStart+params.AeonLength {
		return fmt.Errorf("invalid creation height %v for aeon start %v", bie.CreationHeight, bie.AeonStart)
	}

	// Check theshold is correct
	slashingFraction := float64(params.SlashingThresholdPercentage) * 0.01
	slashingThreshold := int64(slashingFraction * float64(valset.Size()))
	if slashingThreshold != bie.Threshold {
		return fmt.Errorf("incorrect Threshold. Got %v, expected %v", bie.Threshold, slashingThreshold)
	}

	// Check both complainant and defendant addresses are in DKG validator set at aeon start - 1, and that they are in qual
	defIndex, val := valset.GetByAddress(bie.DefendantAddress)
	if val == nil {
		return fmt.Errorf("defendant address %X was not a validator at height %v", bie.DefendantAddress, bie.ValidatorHeight())
	}
	comIndex, val := valset.GetByAddress(bie.ComplainantAddress)
	if val == nil {
		return fmt.Errorf("complainant address %X was not a validator at height %v", bie.ComplainantAddress, bie.ValidatorHeight())
	}
	defInQual := false
	comInQual := false
	for _, valIndex := range blockEntropy.Qual {
		if valIndex == int64(defIndex) {
			defInQual = true
		} else if valIndex == int64(comIndex) {
			comInQual = true
		}

		if defInQual && comInQual {
			break
		}
	}
	if !defInQual || !comInQual {
		return fmt.Errorf("address not in qual: defendant in qual %v, complainant in qual %v", defInQual, comInQual)
	}

	if !val.PubKey.VerifyBytes(bie.SignBytes(chainID), bie.ComplainantSignature) {
		return fmt.Errorf("ComplainantSignature invalid")
	}

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

// DKGEvidence contains evidence a validator caused the DKG to fail
type DKGEvidence struct {
	CreationHeight       int64          // Height evidence was created
	CreationTime         time.Time      // Time evidence was created
	DefendantAddress     crypto.Address // Address of validator accused of inactivity
	ComplainantAddress   crypto.Address // Address of validator submitting complaint complaint
	ValHeight            int64          // Height for obtaining dkg validators
	DKGID                int64          // Identifier for dkg run
	DKGIteration         int64          // Iteration of dkg run
	Threshold            int64          // Threshold of complaints for slashing (depends on validator size)
	ComplainantSignature []byte
}

var _ Evidence = &DKGEvidence{}

// NewDKGEvidence creates DKGEvidence
func NewDKGEvidence(height int64, defAddress crypto.Address, comAddress crypto.Address, validatorHeight int64, dkgID int64, dkgIteration int64, threshold int64) *DKGEvidence {
	return &DKGEvidence{
		CreationHeight:     height,
		CreationTime:       time.Now(),
		DefendantAddress:   defAddress,
		ComplainantAddress: comAddress,
		ValHeight:          validatorHeight,
		DKGID:              dkgID,
		DKGIteration:       dkgIteration,
		Threshold:          threshold,
	}
}

// String returns a string representation of the evidence.
func (de *DKGEvidence) String() string {
	return fmt.Sprintf("DefendantPubKey: %s, ComplainantPubKey: %s, DKGID: %v, DKGIteration: %v", de.DefendantAddress,
		de.ComplainantAddress, de.DKGID, de.DKGIteration)

}

// Height returns evidence was created
func (de *DKGEvidence) Height() int64 {
	return de.CreationHeight
}

// ValidatorHeight returns validator height
func (de *DKGEvidence) ValidatorHeight() int64 {
	return de.ValHeight
}

// Time return
func (de *DKGEvidence) Time() time.Time {
	return de.CreationTime
}

// Address returns the address of the validator.
func (de *DKGEvidence) Address() []byte {
	return de.DefendantAddress
}

// Bytes returns the evidence as byte slice
func (de *DKGEvidence) Bytes() []byte {
	return cdcEncode(de)
}

// Hash returns the hash of the unique fields in evidence. Prevents submission
// of multiple evidence by using a different creation time or signature
func (de *DKGEvidence) Hash() []byte {
	uniqueInfo := struct {
		DefendantAddress   []byte
		ComplainantAddress []byte
		ValidatorHeight    int64
		DKGID              int64
		DKGIteration       int64
		Threshold          int64
	}{de.DefendantAddress, de.ComplainantAddress, de.ValHeight, de.DKGID, de.DKGIteration, de.Threshold}
	return tmhash.Sum(cdcEncode(uniqueInfo))
}

// Verify validates information contained in Evidence. Ensures signature verifies with complainant address, valid validator height and
// that the evidence was created after the aeon start
func (de *DKGEvidence) Verify(chainID string, blockEntropy BlockEntropy, valset *ValidatorSet,
	params EntropyParams) error {
	// Check dkg id is correct
	if blockEntropy.DKGID+1 != de.DKGID {
		return fmt.Errorf("incorrect dkg id. Got %v, expected %v", de.DKGID, blockEntropy.DKGID+1)
	}
	// Check val height corresponds to last aeon starts
	if blockEntropy.NextAeonStart != de.ValHeight {
		return fmt.Errorf("incorrect validator height. Got %v, expected %v", de.ValHeight, blockEntropy.NextAeonStart)
	}
	// Creation height of evidence after dkg has started
	if de.CreationHeight <= de.ValHeight {
		return fmt.Errorf("invalid creation height %v for validator height %v", de.CreationHeight, de.ValHeight)
	}

	// Check theshold is correct
	slashingFraction := float64(params.SlashingThresholdPercentage) * 0.01
	slashingThreshold := int64(slashingFraction * float64(valset.Size()))
	if slashingThreshold != de.Threshold {
		return fmt.Errorf("incorrect Threshold. Got %v, expected %v", de.Threshold, slashingThreshold)
	}

	// Check both complainant and defendant addresses are in DKG validator set at validator height
	_, val := valset.GetByAddress(de.DefendantAddress)
	if val == nil {
		return fmt.Errorf("defendant address %X was not a validator at height %v", de.DefendantAddress, de.ValidatorHeight())
	}
	_, val = valset.GetByAddress(de.ComplainantAddress)
	if val == nil {
		return fmt.Errorf("complainant address %X was not a validator at height %v", de.ComplainantAddress, de.ValidatorHeight())
	}

	if !val.PubKey.VerifyBytes(de.SignBytes(chainID), de.ComplainantSignature) {
		return fmt.Errorf("ComplainantSignature invalid")
	}

	return nil
}

// For signing with private key
func (de DKGEvidence) SignBytes(chainID string) []byte {
	de.ComplainantSignature = nil
	bz, err := cdc.MarshalBinaryLengthPrefixed(de)
	if err != nil {
		panic(err)
	}
	return append([]byte(chainID), bz...)
}

// Equal checks if two pieces of evidence are equal.
func (de *DKGEvidence) Equal(ev Evidence) bool {
	if _, ok := ev.(*DKGEvidence); !ok {
		return false
	}

	// just check their hashes
	deHash := tmhash.Sum(cdcEncode(de))
	evHash := tmhash.Sum(cdcEncode(ev))
	return bytes.Equal(deHash, evHash)
}

// ValidateBasic performs basic validation.
func (de *DKGEvidence) ValidateBasic() error {
	if len(de.ComplainantAddress) == 0 {
		return errors.New("empty ComplainantAddress")
	}
	if len(de.DefendantAddress) == 0 {
		return errors.New("empty DefendantAddress")
	}
	if de.ValHeight <= 0 {
		return errors.New("invalid validator height")
	}
	if de.DKGID < 0 {
		return errors.New("invalid dkg id")
	}
	if de.DKGIteration < 0 {
		return errors.New("invalid dkg iteration")
	}
	if len(de.ComplainantSignature) == 0 {
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
