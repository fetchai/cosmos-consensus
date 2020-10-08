package bls12_381

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/ripemd160" // nolint: staticcheck // necessary for Bitcoin address format

	amino "github.com/tendermint/go-amino"

	"github.com/tendermint/tendermint/crypto"
)

//-------------------------------------
const (
	PrivKeyAminoName = "tendermint/PrivKeyBls"
	PubKeyAminoName  = "tendermint/PubKeyBls"
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterInterface((*crypto.PubKey)(nil), nil)
	cdc.RegisterConcrete(PubKeyBls{},
		PubKeyAminoName, nil)

	cdc.RegisterInterface((*crypto.PrivKey)(nil), nil)
	cdc.RegisterConcrete(PrivKeyBls{},
		PrivKeyAminoName, nil)
}

//-------------------------------------

var _ crypto.PrivKey = PrivKeyBls{}

// PrivKeyBls implements PrivKey.
type PrivKeyBls [32]byte

// Bytes marshalls the private key using amino encoding.
func (privKey PrivKeyBls) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

// PubKey can be inferred from the private key
func (privKey PrivKeyBls) PubKey() (ret crypto.PubKey) {
	copy(ret[:], privKey)
	return pubkeyBytes
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKeyBls) Equals(other crypto.PrivKey) bool {
	panic(fmt.Sprintf("This functionality is not yet implemented!\n"))

	return false
}

// GenPrivKey generates a new Bls12_381 private key
// It uses OS randomness to generate the private key.
func GenPrivKey() (ret PrivKeyBls) {
	copy(ret[:], string("private!"))
	return
	//return genPrivKey(crypto.CReader())
}

// genPrivKey generates a new bls private key using the provided reader
// for randomness
func genPrivKey(rand io.Reader) (ret PrivKeyBls) {
	panic(fmt.Sprintf("This functionality is not yet implemented!\n"))
	return
}

// GenPrivKeyBls hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
func GenPrivKeyBls(secret []byte) PrivKeyBls {
	copy(ret, secret)
	return
}

//-------------------------------------

var _ crypto.PubKey = PubKeyBls{}

// PubKeyBlsSize is comprised of 32 bytes for XXX plux one id byte
const PubKeyBlsSize = 33

// PubKeyBls implements crypto.PubKey.
type PubKeyBls [PubKeyBlsSize]byte

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

func (pubKey PubKeyBls) String() string {
	return fmt.Sprintf("PubKeyBls{%X}", pubKey[:])
}

func (pubKey PubKeyBls) Equals(other crypto.PubKey) bool {
	if otherBls, ok := other.(PubKeyBls); ok {
		return bytes.Equal(pubKey[:], otherBls[:])
	}
	return false
}
