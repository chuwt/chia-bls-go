package bls

import (
	"crypto/sha512"
	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
)

func KeyGen(seed []byte) PrivateKey {
	L := 48
	okm := extractExpand(L, append(seed, 0), []byte("BLS-SIG-KEYGEN-SALT-"), []byte{0, byte(L)})

	return PrivateKey{new(big.Int).Mod(new(big.Int).SetBytes(okm), bls12381.NewG1().Q())}
}

func KeyGenWithMnemonic(mnemonic, password string) PrivateKey {
	seed := newSeed(mnemonic, password)
	return KeyGen(seed)
}

func newSeed(mnemonic, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}