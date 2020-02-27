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
	if aeonKeys.CanSign() {
		if newPrivValidator == nil {
			panic(fmt.Errorf("aeonDetails has DKG keys but no privValidator"))
		}
		index, _ := validators.GetByAddress(newPrivValidator.GetPubKey().Address())
		if index < 0 {
			panic(fmt.Errorf("aeonDetails has DKG keys but not in validators"))
		}
		if !aeonKeys.CheckIndex(uint64(index)) {
			panic(fmt.Errorf("aeonDetails has DKG keys not matching validator index"))
		}
	}
	ad := &aeonDetails{
		privValidator: newPrivValidator,
		validators:    validators,
		aeonExecUnit:  aeonKeys,
		threshold:     validators.Size()/2 + 1,
	}

	return ad
}
