package bls12_381

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/pkg/errors"

	"golang.org/x/crypto/ripemd160" // nolint: staticcheck // necessary for Bitcoin address format

	amino "github.com/tendermint/go-amino"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/mcl_cpp"
)

//-------------------------------------
const (
	PrivKeyAminoName = "tendermint/PrivKeyBls"
	PubKeyAminoName  = "tendermint/PubKeyBls"
	SignatureSize    = 96
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(PubKeyBls{},
		PubKeyAminoName, nil)

	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)
	cdc.RegisterConcrete(PrivKeyBls{},
		PrivKeyAminoName, nil)

	mcl_cpp.InitialiseMcl()
}

//-------------------------------------

var _ crypto.PrivKey = PrivKeyBls{}

const PrivKeyBlsSize = 64

// PrivKeyBls implements PrivKey.
type PrivKeyBls [PrivKeyBlsSize]byte

// Reference empty priv key
var emptyPrivKey PrivKeyBls = PrivKeyBls{}

func (privKey PrivKeyBls) String() (ret string) {
	asByte := [PrivKeyBlsSize]byte(privKey)
	ret = string(asByte[:])
	return
}

// Function to check there is actually a private key set
func (privKey PrivKeyBls) IsEmpty() bool {
	return bytes.Equal(privKey[:], emptyPrivKey[:])
}

// Sign - for now this is just the SHA2 of the message
// TODO(HUT): not secure.
func (privKey PrivKeyBls) Sign(msg []byte) (ret []byte, err error) {
	sig := mcl_cpp.Sign(string(msg), privKey.String())

	if privKey.IsEmpty() {
		return ret, errors.New("Attempt to sign with empty priv key is invalid")
	}

	if len(msg) == 0 {
		return ret, errors.New("Attempt to sign an empty message is invalid")
	}

	return []byte(sig), nil
}

// Bytes marshalls the private key using amino encoding.
func (privKey PrivKeyBls) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

// PubKey can be inferred from the private key
func (privKey PrivKeyBls) PubKey() crypto.PubKey {
	pubKeyWithPoP := mcl_cpp.PubKeyFromPrivateWithPoP(privKey.String())
	pubKey := pubKeyWithPoP.GetFirst()
	pop := pubKeyWithPoP.GetSecond()

	newKey := PubKeyBls{}

	if len(pubKey) != PubKeyBlsSize {
		panic(fmt.Sprintf("Didn't get a pub key of the correct size! Got: %v, Expected %v\n", len(pubKey), PubKeyBlsSize))
	}

	if len(pop) != PopBlsSize {
		panic(fmt.Sprintf("Didn't get a bls PoP of the correct size! Got: %v, Expected %v\n", len(pop), PopBlsSize))
	}

	// Combine the two
	//pubKey = append(pubKey, pop)

	copy(newKey[0:PubKeyBlsSize], pubKey[:])
	copy(newKey[PubKeyBlsSize+1:], pop[:])

	return newKey
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeyBls) Equals(other crypto.PrivKey) bool {

	asBls, ok := other.(PrivKeyBls)

	if !ok {
		return false
	}

	return bytes.Equal(privKey[:], asBls[:])
}

// GenPrivKey generates a new bls12_381 private key
// It uses OS randomness to generate the private key.
func GenPrivKey() (ret PrivKeyBls) {
	privKey := mcl_cpp.GenPrivKey()

	copy(ret[:], privKey)
	return
}

// genPrivKey generates a new bls private key using the provided reader
// for randomness
func genPrivKey(rand io.Reader) (ret PrivKeyBls) {
	panic(fmt.Sprintf("The functionality genPrivKey is not yet implemented!\n"))
	return
}

// GenPrivKeyBls hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
func GenPrivKeyBls(secret []byte) (ret PrivKeyBls) {
	panic(fmt.Sprintf("The functionality GenPrivKeyBls is not yet implemented!\n"))
	return
}

//-------------------------------------

var _ crypto.PubKey = PubKeyBls{}

// PubKeyBlsSize is comprised of 192 bytes for the public key (not including PoP)
const PubKeyBlsSize      = 192
const PopBlsSize         = 192
const TotalPubKeyBlsSize = PubKeyBlsSize + PopBlsSize

// PubKeyBls implements crypto.PubKey.
type PubKeyBls [TotalPubKeyBlsSize]byte

func (pubKey PubKeyBls) VerifyBytes(msg []byte, sig []byte) bool {
	result := mcl_cpp.PairingVerify(string(msg), string(sig), pubKey.RawString())
	return result
}

// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeyBls) Address() crypto.Address {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:]) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return crypto.Address(hasherRIPEMD160.Sum(nil))
}

// Bytes returns the pubkey marshalled with amino encoding.
func (pubKey PubKeyBls) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeyBls) RawString() (ret string) {
	asByte := [TotalPubKeyBlsSize]byte(pubKey)
	ret = string(asByte[:])
	return
}

func (pubKey PubKeyBls) String() string {
	return fmt.Sprintf("PubKeyBls{%X}", pubKey[:])
}

func (pubKey PubKeyBls) Equals(other crypto.PubKey) bool {
	if otherBls, ok := other.(PubKeyBls); ok {
		return bytes.Equal(pubKey[:], otherBls[:])
	}
	return false
}
