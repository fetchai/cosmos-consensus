package beacon

import (
	"fmt"
	"io/ioutil"
	"runtime"

	tmos "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/libs/tempfile"
	"github.com/tendermint/tendermint/types"
)

func newAeonExecUnit(keyType string, generator string, keys DKGKeyInformation, qual IntVector) BaseAeon {
	switch keyType {
	case GetBLS_AEON():
		return NewBlsAeon(generator, keys, qual)
	case GetGLOW_AEON():
		return NewGlowAeon(generator, keys, qual)
	default:
		panic(fmt.Errorf("Unknown type %v", keyType))
	}
}

// aeonDetails stores entropy generation details for each aeon
type aeonDetails struct {
	privValidator   types.PrivValidator
	validatorHeight int64 // Height at which validator set obtained
	dkgID           int64
	validators      *types.ValidatorSet
	threshold       int
	aeonExecUnit    BaseAeon
	// start and end are inclusive
	Start int64
	End   int64

	qual []int64
}

// LoadAeonDetails creates aeonDetails from keys saved in file
func loadAeonDetails(aeonDetailsFile *AeonDetailsFile, validators *types.ValidatorSet, privVal types.PrivValidator) *aeonDetails {
	if len(aeonDetailsFile.PublicInfo.GroupPublicKey) == 0 {
		return keylessAeonDetails(aeonDetailsFile.PublicInfo.Start, aeonDetailsFile.PublicInfo.End)
	}

	keys := NewDKGKeyInformation()
	keys.SetGroup_public_key(aeonDetailsFile.PublicInfo.GroupPublicKey)
	keys.SetPrivate_key(aeonDetailsFile.PrivateKey)
	keyShares := NewStringVector()
	for i := 0; i < len(aeonDetailsFile.PublicInfo.PublicKeyShares); i++ {
		keyShares.Add(aeonDetailsFile.PublicInfo.PublicKeyShares[i])
	}
	keys.SetPublic_key_shares(keyShares)
	qual := NewIntVector()
	for i := 0; i < len(aeonDetailsFile.PublicInfo.Qual); i++ {
		qual.Add(uint(aeonDetailsFile.PublicInfo.Qual[i]))
	}

	keyType := aeonDetailsFile.PublicInfo.KeyType
	if len(keyType) == 0 {
		// If no key type in file, attempt to use the default type specified in beacon_setup_service.hpp
		keyType = GetAeonType()
	}

	aeonExecUnit := newAeonExecUnit(keyType, aeonDetailsFile.PublicInfo.Generator, keys, qual)
	aeonDetails, _ := newAeonDetails(privVal, aeonDetailsFile.PublicInfo.ValidatorHeight, aeonDetailsFile.PublicInfo.DKGID, validators, aeonExecUnit,
		aeonDetailsFile.PublicInfo.Start, aeonDetailsFile.PublicInfo.End)
	return aeonDetails
}

// newAeonDetails creates new aeonDetails, checking validity of inputs. Can only be used within this package
func newAeonDetails(newPrivValidator types.PrivValidator, valHeight int64, id int64,
	validators *types.ValidatorSet, aeonKeys BaseAeon,
	startHeight int64, endHeight int64) (*aeonDetails, error) {
	if valHeight <= 0 {
		panic(fmt.Errorf("aeonDetails in validator height less than 1"))
	}
	if validators == nil {
		panic(fmt.Sprintf("aeonDetails with nil validator set"))
	}
	if aeonKeys == nil {
		panic(fmt.Errorf("aeonDetails with nil active execution unit"))
	}
	if startHeight <= 0 || endHeight < startHeight {
		panic(fmt.Errorf("aeonDetails invalid start/end height"))
	}
	if aeonKeys.CanSign() {
		if newPrivValidator == nil {
			panic(fmt.Errorf("aeonDetails has DKG keys but no privValidator"))
		}
		pubKey, err := newPrivValidator.GetPubKey()
		if err == nil {
			index, _ := validators.GetByAddress(pubKey.Address())
			if index < 0 || !aeonKeys.InQual(uint(index)) {
				panic(fmt.Errorf("aeonDetails has DKG keys but not in validators or qual"))
			}
			if !aeonKeys.CheckIndex(uint(index)) {
				i := 0
				for !aeonKeys.CheckIndex(uint(i)) && i < validators.Size() {
					i++
				}
				panic(fmt.Errorf("aeonDetails has DKG keys index %v not matching validator index %v", i, index))
			}
		}

	}
	qual := aeonKeys.Qual()

	ad := &aeonDetails{
		privValidator:   newPrivValidator,
		validatorHeight: valHeight,
		dkgID:           id,
		validators:      types.NewValidatorSet(validators.Validators),
		aeonExecUnit:    aeonKeys,
		threshold:       validators.Size()/2 + 1,
		Start:           startHeight,
		End:             endHeight,
		qual:            make([]int64, qual.Size()),
	}
	for i := 0; i < int(qual.Size()); i++ {
		ad.qual[i] = int64(qual.Get(i))
	}

	runtime.SetFinalizer(ad,
		func(ad *aeonDetails) {
			DeleteBaseAeon(ad.aeonExecUnit)
		})

	return ad, nil
}

func keylessAeonDetails(aeonStart int64, aeonEnd int64) *aeonDetails {
	return &aeonDetails{
		Start: aeonStart,
		End:   aeonEnd,
	}
}

func (aeon *aeonDetails) dkgOutput() *DKGOutput {
	if aeon.aeonExecUnit == nil {
		return &DKGOutput{
			Start: aeon.Start,
			End:   aeon.End,
		}
	}
	output := DKGOutput{
		KeyType:         aeon.aeonExecUnit.Name(),
		GroupPublicKey:  aeon.aeonExecUnit.GroupPublicKey(),
		Generator:       aeon.aeonExecUnit.Generator(),
		PublicKeyShares: make([]string, len(aeon.validators.Validators)),
		ValidatorHeight: aeon.validatorHeight,
		DKGID:           aeon.dkgID,
		Qual:            aeon.qual,
		Start:           aeon.Start,
		End:             aeon.End,
	}
	publicKeyShares := aeon.aeonExecUnit.PublicKeyShares()
	for i := 0; i < int(publicKeyShares.Size()); i++ {
		output.PublicKeyShares[i] = publicKeyShares.Get(i)
	}
	return &output
}

func (aeon *aeonDetails) IsKeyless() bool {
	return aeon.aeonExecUnit == nil
}

// Save a number of aeonDetails to a file
func saveAeons(filePath string, aeons ...*aeonDetails) {

	var aeonQueue []*AeonDetailsFile

	for _, aeon := range aeons {

		if aeon == nil {
			panic(fmt.Sprintf("Attempt to save nil aeon(s) to file: %v %v\n", filePath, aeons))
		}

		aeonFile := AeonDetailsFile{
			PublicInfo: *aeon.dkgOutput(),
		}
		if aeon.aeonExecUnit != nil {
			aeonFile.PrivateKey = aeon.aeonExecUnit.PrivateKey()
		}

		aeonQueue = append(aeonQueue, &aeonFile)
	}

	saveAeonQueue(filePath, aeonQueue)
}

// AeonDetailsFile is struct for saving aeon keys to file
type AeonDetailsFile struct {
	PublicInfo DKGOutput `json:"public_info"`
	PrivateKey string    `json:"private_key"`
}

func (aeonFile *AeonDetailsFile) IsForSamePeriod(other *AeonDetailsFile) bool {
	if (other != nil) && (aeonFile.PublicInfo.Start == other.PublicInfo.Start) && (aeonFile.PublicInfo.End == other.PublicInfo.End) {
		return true
	}

	return false
}

// Save creates json with aeon details
func saveAeonQueue(outFile string, aeonFiles []*AeonDetailsFile) {
	jsonBytes, err := cdc.MarshalJSONIndent(aeonFiles, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

// LoadAeonDetailsFile creates a queue of AeonDetailsFiles from json
func loadAeonDetailsFiles(filePath string) ([]*AeonDetailsFile, error) {
	jsonBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		tmos.Exit(err.Error())
	}
	var aeonQueue []*AeonDetailsFile

	err = cdc.UnmarshalJSON(jsonBytes, &aeonQueue)
	if err != nil {
		tmos.Exit(fmt.Sprintf("Error reading AeonDetailsFiles from %v: %v\n", filePath, err))
	}

	for _, aeon := range aeonQueue {
		err = aeon.ValidateBasic()

		if err != nil {
			break
		}
	}

	return aeonQueue, err
}

// ValidateBasic for basic validity checking of aeon file
func (aeonFile *AeonDetailsFile) ValidateBasic() error {
	err := aeonFile.PublicInfo.ValidateBasic()
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

// DKGOutput is struct for broadcasting dkg completion info
type DKGOutput struct {
	KeyType         string   `json:"key_type"`
	GroupPublicKey  string   `json:"group_public_key"`
	PublicKeyShares []string `json:"public_key_shares"`
	Generator       string   `json:"generator"`
	ValidatorHeight int64    `json:"validator_height"`
	DKGID           int64    `json:"dkg_id"`
	Qual            []int64  `json:"qual"`
	Start           int64    `json:"start"`
	End             int64    `json:"end"`
}

// ValidateBasic for basic validity checking of dkg output
func (output *DKGOutput) ValidateBasic() error {
	if len(output.GroupPublicKey) != 0 {
		if len(output.Generator) == 0 {
			return fmt.Errorf("Empty generator")
		}
		if output.ValidatorHeight <= 0 {
			return fmt.Errorf("Invalid validator height %v", output.ValidatorHeight)
		}
		if len(output.Qual) == 0 || len(output.Qual) != len(output.PublicKeyShares) {
			return fmt.Errorf("Mismatch in qual size %v and public key shares %v", len(output.Qual), len(output.PublicKeyShares))
		}
		if output.DKGID < 0 {
			return fmt.Errorf("Invalid dkg id %v", output.DKGID)
		}
	}
	if output.Start <= 0 || output.End < output.Start {
		return fmt.Errorf("Invalid start %v or end %v", output.Start, output.End)
	}
	return nil
}
