package beacon

import (
	"fmt"
	"io/ioutil"
	"runtime"

	tmos "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/libs/tempfile"
	"github.com/tendermint/tendermint/mcl_cpp"
	"github.com/tendermint/tendermint/types"
)

// aeonDetails stores entropy generation details for each aeon
type aeonDetails struct {
	privValidator   types.PrivValidator
	validatorHeight int64 // Height at which validator set obtained
	dkgID           int64
	validators      *types.ValidatorSet
	threshold       int
	aeonExecUnit    mcl_cpp.BaseAeon
	// start and end are inclusive
	Start int64
	End   int64

	qual []int64
}

// newAeonDetails creates new aeonDetails, checking validity of inputs. Can only be used within this package
func newAeonDetails(newPrivValidator types.PrivValidator, valHeight int64, id int64,
	validators *types.ValidatorSet, aeonKeys mcl_cpp.BaseAeon,
	startHeight int64, endHeight int64) (*aeonDetails, error) {
	if validators == nil || aeonKeys == nil {
		return nil, fmt.Errorf("aeonDetails with invalid vals %v and/or active execution unit %v", validators, aeonKeys)
	}
	qualSize := int(aeonKeys.Qual().Size())
	ad := &aeonDetails{
		privValidator:   newPrivValidator,
		validatorHeight: valHeight,
		dkgID:           id,
		validators:      types.NewValidatorSet(validators.Validators),
		aeonExecUnit:    aeonKeys,
		threshold:       validators.Size()/2 + 1,
		Start:           startHeight,
		End:             endHeight,
		qual:            make([]int64, qualSize),
	}
	for i := 0; i < qualSize; i++ {
		ad.qual[i] = int64(aeonKeys.Qual().Get(i))
	}
	err := ad.checkKeys()
	if err != nil {
		return nil, err
	}

	runtime.SetFinalizer(ad,
		func(ad *aeonDetails) {
			mcl_cpp.DeleteBaseAeon(ad.aeonExecUnit)
		})

	return ad, nil
}

func (ad *aeonDetails) checkKeys() error {
	if !ad.aeonExecUnit.CheckKeys() {
		return fmt.Errorf("Failed to deserialise mcl objects")
	}
	if ad.aeonExecUnit.CanSign() {
		if ad.privValidator == nil {
			return fmt.Errorf("aeonDetails has DKG keys but no privValidator")
		}
		pubKey, err := ad.privValidator.GetPubKey()
		if err == nil {
			index, _ := ad.validators.GetByAddress(pubKey.Address())
			if index < 0 || !ad.aeonExecUnit.InQual(uint(index)) {
				return fmt.Errorf("aeonDetails has DKG keys but not in validators or qual")
			}
			if !ad.aeonExecUnit.CheckIndex(uint(index)) {
				i := 0
				for !ad.aeonExecUnit.CheckIndex(uint(i)) && i < ad.validators.Size() {
					i++
				}
				return fmt.Errorf("aeonDetails has DKG keys index %v not matching validator index %v", i, index)
			}
		}
	}
	return nil
}

// Creates aeon details without any signing or verification keys. Used to bridge gaps in entropy generation.
func keylessAeonDetails(dkgID int64, validatorHeight int64, aeonStart int64, aeonEnd int64) *aeonDetails {
	return &aeonDetails{
		dkgID:           dkgID,
		validatorHeight: validatorHeight,
		Start:           aeonStart,
		End:             aeonEnd,
	}
}

func (aeon *aeonDetails) dkgOutput() *DKGOutput {
	output := DKGOutput{
		Start:           aeon.Start,
		End:             aeon.End,
		DKGID:           aeon.dkgID,
		ValidatorHeight: aeon.validatorHeight,
	}
	if aeon.IsKeyless() {
		return &output
	}
	output.KeyType = aeon.aeonExecUnit.Name()
	output.GroupPublicKey = aeon.aeonExecUnit.GroupPublicKey()
	output.Generator = aeon.aeonExecUnit.Generator()
	output.PublicKeyShares = make([]string, len(aeon.validators.Validators))
	output.Qual = aeon.qual
	publicKeyShares := aeon.aeonExecUnit.PublicKeyShares()
	for i := 0; i < int(publicKeyShares.Size()); i++ {
		output.PublicKeyShares[i] = publicKeyShares.Get(i)
	}
	return &output
}

func (aeon *aeonDetails) IsKeyless() bool {
	return aeon.aeonExecUnit == nil
}

//--------------------------------------------------------------------------

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

// ValidateBasic for basic validity checking of aeon file
func (aeonFile *AeonDetailsFile) ValidateBasic() error {
	err := aeonFile.PublicInfo.ValidateBasic()
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

//-----------------------------------------------------------------------------------

// LoadAeonDetails creates aeonDetails from keys saved in file
func loadAeonDetails(aeonDetailsFile *AeonDetailsFile, validators *types.ValidatorSet, privVal types.PrivValidator) (*aeonDetails, error) {
	if len(aeonDetailsFile.PublicInfo.GroupPublicKey) == 0 {
		return keylessAeonDetails(aeonDetailsFile.PublicInfo.DKGID, aeonDetailsFile.PublicInfo.ValidatorHeight,
			aeonDetailsFile.PublicInfo.Start, aeonDetailsFile.PublicInfo.End), nil
	}

	keys := mcl_cpp.NewDKGKeyInformation()
	keys.SetGroup_public_key(aeonDetailsFile.PublicInfo.GroupPublicKey)
	keys.SetPrivate_key(aeonDetailsFile.PrivateKey)
	keyShares := mcl_cpp.NewStringVector()
	for i := 0; i < len(aeonDetailsFile.PublicInfo.PublicKeyShares); i++ {
		keyShares.Add(aeonDetailsFile.PublicInfo.PublicKeyShares[i])
	}
	keys.SetPublic_key_shares(keyShares)
	qual := mcl_cpp.NewIntVector()
	for i := 0; i < len(aeonDetailsFile.PublicInfo.Qual); i++ {
		qual.Add(uint(aeonDetailsFile.PublicInfo.Qual[i]))
	}

	keyType := aeonDetailsFile.PublicInfo.KeyType
	if len(keyType) == 0 {
		// If no key type in file, attempt to use the default type specified in beacon_setup_service.hpp
		keyType = mcl_cpp.GetAeonType()
	}

	aeonExecUnit := mcl_cpp.NewAeonExecUnit(keyType, aeonDetailsFile.PublicInfo.Generator, keys, qual)
	aeonDetails, err := newAeonDetails(privVal, aeonDetailsFile.PublicInfo.ValidatorHeight, aeonDetailsFile.PublicInfo.DKGID, validators, aeonExecUnit,
		aeonDetailsFile.PublicInfo.Start, aeonDetailsFile.PublicInfo.End)
	if err != nil {
		return nil, err
	}
	return aeonDetails, nil
}

// Add aon aeon to the file, keeping a max of N aeons in the file (reading
// from the file and appending if neccessary)
func updateFileAeons(filePath string, max int, aeons ...*aeonDetails) {

	fmt.Printf("updating old!\n") // DELETEME_NH
  aeonsInFile, _ := loadAeonDetailsFiles(filePath)

  // Now we have potential aeons in the file, and we want the older of these
  // to be at the front, so append the ones we want to write
  //aeons = append(aeonsInFile, aeons)

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

		aeonsInFile = append(aeonsInFile, &aeonFile)
	}

	// Now write back to the file the last N of these
	if len(aeonsInFile) > max {
		aeonsInFile = aeonsInFile[len(aeonsInFile) - max:]
	}

	saveAeonQueue(filePath, aeonsInFile)
	fmt.Printf("updated old!\n") // DELETEME_NH
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
