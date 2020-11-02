package types

const (
	PubKeyBls12_381 = "bls12_381"
)

func Bls12_381ValidatorUpdate(pubkey []byte, power int64) ValidatorUpdate {
	return ValidatorUpdate{
		// Address:
		PubKey: PubKey{
			Type: PubKeyBls12_381,
			Data: pubkey,
		},
		Power: power,
	}
}
