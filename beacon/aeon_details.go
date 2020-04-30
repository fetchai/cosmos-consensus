package beacon

import (
	"fmt"
	"io/ioutil"

	tmos "github.com/tendermint/tendermint/libs/os"
	"github.com/tendermint/tendermint/libs/tempfile"
	"github.com/tendermint/tendermint/types"
)

// aeonDetails stores entropy generation details for each aeon
type aeonDetails struct {
	privValidator types.PrivValidator
	validators    *types.ValidatorSet
	threshold     int
	aeonExecUnit  AeonExecUnit
	// start and end are inclusive
	Start int64
	End   int64
}

// LoadAeonDetails creates aeonDetails from keys saved in file
func LoadAeonDetails(filePath string, validators *types.ValidatorSet, privVal types.PrivValidator) (error, *aeonDetails) {
	err, aeonDetailsFile := loadAeonDetailsFile(filePath)

	keys := NewDKGKeyInformation()
	keys.SetGroup_public_key(aeonDetailsFile.GroupPublicKey)
	keys.SetPrivate_key(aeonDetailsFile.PrivateKey)
	keyShares := NewStringVector()
	for i := 0; i < len(aeonDetailsFile.PublicKeyShares); i++ {
		keyShares.Add(aeonDetailsFile.PublicKeyShares[i])
	}
	keys.SetPublic_key_shares(keyShares)
	qual := NewIntVector()
	for i := 0; i < len(aeonDetailsFile.Qual); i++ {
		qual.Add(aeonDetailsFile.Qual[i])
	}

	aeonExecUnit := NewAeonExecUnit(aeonDetailsFile.Generator, keys, qual)
	aeonDetails := newAeonDetails(validators, privVal, aeonExecUnit, aeonDetailsFile.Start, aeonDetailsFile.End)
	return err, aeonDetails
}

// newAeonDetails creates new aeonDetails, checking validity of inputs. Can only be used within this package
func newAeonDetails(
	validators *types.ValidatorSet, newPrivValidator types.PrivValidator, aeonKeys AeonExecUnit,
	startHeight int64, endHeight int64) *aeonDetails {
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
			panic(fmt.Errorf("aeonDetails has DKG keys not matching validator index"))
		}
	}

	ad := &aeonDetails{
		privValidator: newPrivValidator,
		validators:    newVals,
		aeonExecUnit:  aeonKeys,
		threshold:     validators.Size()/2 + 1,
		Start:         startHeight,
		End:           endHeight,
	}

	return ad
}

func (aeon *aeonDetails) save(filePath string) {
	aeonFile := AeonDetailsFile{
		GroupPublicKey:  aeon.aeonExecUnit.GroupPublicKey(),
		PrivateKey:      aeon.aeonExecUnit.PrivateKey(),
		Generator:       aeon.aeonExecUnit.Generator(),
		PublicKeyShares: make([]string, len(aeon.validators.Validators)),
		Qual:            make([]uint, len(aeon.validators.Validators)),
		Start:           aeon.Start,
		End:             aeon.End,
	}

	publicKeyShares := aeon.aeonExecUnit.PublicKeyShares()
	for i := 0; i < int(publicKeyShares.Size()); i++ {
		aeonFile.PublicKeyShares[i] = publicKeyShares.Get(i)
	}
	qual := aeon.aeonExecUnit.Qual()
	for i := 0; i < int(qual.Size()); i++ {
		aeonFile.Qual[i] = qual.Get(i)
	}
	aeonFile.save(filePath)
}

// AeonDetailsFile is struct for saving aeon keys to file
type AeonDetailsFile struct {
	GroupPublicKey  string   `json:"group_public_key"`
	PrivateKey      string   `json:"private_key"`
	PublicKeyShares []string `json:"public_key_shares"`
	Generator       string   `json:"generator"`
	Qual            []uint   `json:"qual"`
	Start           int64    `json:"start"`
	End             int64    `json:"end"`
}

// Save creates json with aeon details
func (aeonFile *AeonDetailsFile) save(outFile string) {
	jsonBytes, err := cdc.MarshalJSONIndent(aeonFile, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

// LoadAeonDetailsFile creates AeonDetailsFile from json
func loadAeonDetailsFile(filePath string) (error, *AeonDetailsFile) {
	jsonBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		tmos.Exit(err.Error())
	}
	aeonFile := AeonDetailsFile{}
	err = cdc.UnmarshalJSON(jsonBytes, &aeonFile)
	if err != nil {
		tmos.Exit(fmt.Sprintf("Error reading AeonDetailsFile from %v: %v\n", filePath, err))
	}
	err = aeonFile.ValidateBasic()
	return err, &aeonFile
}

func (aeonFile *AeonDetailsFile) ValidateBasic() error {
	if len(aeonFile.GroupPublicKey) == 0 {
		return fmt.Errorf("Empty group public key")
	}
	if len(aeonFile.Generator) == 0 {
		return fmt.Errorf("Empty generator")
	}
	if len(aeonFile.Qual) == 0 || len(aeonFile.Qual) != len(aeonFile.PublicKeyShares) {
		return fmt.Errorf("Mismatch in qual size %v and public key shares %v", len(aeonFile.Qual), len(aeonFile.PublicKeyShares))
	}
	if aeonFile.Start <= 0 || aeonFile.End < aeonFile.Start {
		return fmt.Errorf("Invalid start %v or end %v", aeonFile.Start, aeonFile.End)
	}
	return nil
}
