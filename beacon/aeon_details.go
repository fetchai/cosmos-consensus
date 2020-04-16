package beacon

import (
	"fmt"

	"github.com/tendermint/tendermint/types"
)

// aeonDetails stores entropy generation details for each aeon
type aeonDetails struct {
	privValidator types.PrivValidator
	validators    *types.ValidatorSet
	threshold     int
	aeonExecUnit  AeonExecUnit
	start         int64
	end           int64
}

// NewAeonDetails creates new aeonDetails, checking validity of inputs
func NewAeonDetails(
	validators *types.ValidatorSet, newPrivValidator types.PrivValidator, aeonKeys AeonExecUnit) *aeonDetails {
	if validators == nil {
		panic(fmt.Sprintf("aeonDetails with nil validator set"))
	}
	if aeonKeys == nil {
		panic(fmt.Errorf("aeonDetails with nil active execution unit"))
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
	}

	return ad
}
