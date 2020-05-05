package beacon

import (
	"fmt"
	"io/ioutil"

	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/types"
)

// aeonDetails stores entropy generation details for each aeon
type aeonDetails struct {
	privValidator   types.PrivValidator
	validatorHeight int64 // Height at which validator set obtained
	validators      *types.ValidatorSet
	threshold       int
	aeonExecUnit    AeonExecUnit
	// start and end are inclusive
	Start int64
	End   int64
}

// LoadAeonDetails creates aeonDetails from keys saved in file
func LoadAeonDetails(aeonDetailsFile *AeonDetailsFile, validators *types.ValidatorSet, privVal types.PrivValidator) *aeonDetails {
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
		qual.Add(aeonDetailsFile.PublicInfo.Qual[i])
	}

	aeonExecUnit := NewAeonExecUnit(aeonDetailsFile.PublicInfo.Generator, keys, qual)
	aeonDetails := newAeonDetails(privVal, aeonDetailsFile.PublicInfo.ValidatorHeight, validators, aeonExecUnit,
		aeonDetailsFile.PublicInfo.Start, aeonDetailsFile.PublicInfo.End)
	return aeonDetails
}

// newAeonDetails creates new aeonDetails, checking validity of inputs. Can only be used within this package
func newAeonDetails(newPrivValidator types.PrivValidator, valHeight int64,
	validators *types.ValidatorSet, aeonKeys AeonExecUnit,
	startHeight int64, endHeight int64) *aeonDetails {
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
	qual := make([]*types.Validator, 0)
	for index := 0; index < len(validators.Validators); index++ {
		if aeonKeys.InQual(uint(index)) {
			qual = append(qual, validators.Validators[index])
		}
	}
	newVals := types.NewValidatorSet(qual)
	if aeonKeys.CanSign() {
		if newPrivValidator == nil {
			panic(fmt.Errorf("aeonDetails has DKG keys but no privValidator"))
		}
		index, _ := newVals.GetByAddress(newPrivValidator.GetPubKey().Address())
		if index < 0 {
			panic(fmt.Errorf("aeonDetails has DKG keys but not in validators"))
		}
		if !aeonKeys.CheckIndex(uint(index)) {
			i := 0
			for !aeonKeys.CheckIndex(uint(i)) && i < validators.Size() {
				i++
			}
			panic(fmt.Errorf("aeonDetails has DKG keys index %v not matching validator index %v", i, index))
		}
	}

	ad := &aeonDetails{
		privValidator:   newPrivValidator,
		validatorHeight: valHeight,
		validators:      newVals,
		aeonExecUnit:    aeonKeys,
		threshold:       validators.Size()/2 + 1,
		Start:           startHeight,
		End:             endHeight,
	}

	return ad
}

func (aeon *aeonDetails) dkgOutput() *DKGOutput {
	output := DKGOutput{
		GroupPublicKey:  aeon.aeonExecUnit.GroupPublicKey(),
		Generator:       aeon.aeonExecUnit.Generator(),
		PublicKeyShares: make([]string, len(aeon.validators.Validators)),
		ValidatorHeight: aeon.validatorHeight,
		Qual:            make([]uint, len(aeon.validators.Validators)),
		Start:           aeon.Start,
		End:             aeon.End,
	}
	publicKeyShares := aeon.aeonExecUnit.PublicKeyShares()
	for i := 0; i < int(publicKeyShares.Size()); i++ {
		output.PublicKeyShares[i] = publicKeyShares.Get(i)
	}
	qual := aeon.aeonExecUnit.Qual()
	for i := 0; i < int(qual.Size()); i++ {
		output.Qual[i] = qual.Get(i)
	}
	return &output
}

func (aeon *aeonDetails) save(filePath string) {
	aeonFile := AeonDetailsFile{
		PublicInfo: *aeon.dkgOutput(),
		PrivateKey: aeon.aeonExecUnit.PrivateKey(),
	}
	aeonFile.save(filePath)
}

// AeonDetailsFile is struct for saving aeon keys to file
type AeonDetailsFile struct {
	PublicInfo DKGOutput `json:"public_info"`
	PrivateKey string    `json:"private_key"`
}

// Save creates json with aeon details
func (aeonFile *AeonDetailsFile) save(outFile string) {
	jsonBytes, err := cdc.MarshalJSONIndent(aeonFile, "", "  ")
	if err != nil {
		panic(err)
	}
	err = cmn.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

// LoadAeonDetailsFile creates AeonDetailsFile from json
func LoadAeonDetailsFile(filePath string) (*AeonDetailsFile, error) {
	jsonBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		cmn.Exit(err.Error())
	}
	aeonFile := AeonDetailsFile{}
	err = cdc.UnmarshalJSON(jsonBytes, &aeonFile)
	if err != nil {
		cmn.Exit(fmt.Sprintf("Error reading AeonDetailsFile from %v: %v\n", filePath, err))
	}
	err = aeonFile.ValidateBasic()
	return &aeonFile, err
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
	GroupPublicKey  string   `json:"group_public_key"`
	PublicKeyShares []string `json:"public_key_shares"`
	Generator       string   `json:"generator"`
	ValidatorHeight int64    `json:"validator_height"`
	Qual            []uint   `json:"qual"`
	Start           int64    `json:"start"`
	End             int64    `json:"end"`
}

// ValidateBasic for basic validity checking of dkg output
func (output *DKGOutput) ValidateBasic() error {
	if len(output.GroupPublicKey) == 0 {
		return fmt.Errorf("Empty group public key")
	}
	if len(output.Generator) == 0 {
		return fmt.Errorf("Empty generator")
	}
	if output.ValidatorHeight <= 0 {
		return fmt.Errorf("Invalid validator height %v", output.ValidatorHeight)
	}
	if len(output.Qual) == 0 || len(output.Qual) != len(output.PublicKeyShares) {
		return fmt.Errorf("Mismatch in qual size %v and public key shares %v", len(output.Qual), len(output.PublicKeyShares))
	}
	if output.Start <= 0 || output.End < output.Start {
		return fmt.Errorf("Invalid start %v or end %v", output.Start, output.End)
	}
	return nil
}
