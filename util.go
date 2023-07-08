package bls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/hkdf"
)

var g1One, _ = hex.DecodeString("" +
	"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" +
	"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
)

func G1Generator() *bls12381.PointG1 {
	one, _ := bls12381.NewG1().FromBytes(g1One)
	return one
}

func extractExpand(L int, key, salt, info []byte) (okm []byte) {
	okm = make([]byte, L)
	_, _ = hkdf.New(sha256.New, key, salt, info).Read(okm)

	return okm
}

func ikmToLamportSk(ikm, salt []byte) []byte {
	return extractExpand(32*255, ikm, salt, nil)
}

func parentSkToLamportPk(parentSk PrivateKey, index int) []byte {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, uint32(index))
	ikm := make([]byte, 32)
	parentSk.value.FillBytes(ikm)
	notIkm := make([]byte, len(ikm))
	for i, e := range ikm {
		notIkm[i] = e ^ 0xFF
	}

	lamport0 := ikmToLamportSk(ikm, salt)
	lamport1 := ikmToLamportSk(notIkm, salt)

	var lamportPk []byte

	for i := 0; i < 255; i++ {
		lamportPk = append(lamportPk, Hash256(lamport0[i*32:(i+1)*32])...)
	}
	for i := 0; i < 255; i++ {
		lamportPk = append(lamportPk, Hash256(lamport1[i*32:(i+1)*32])...)
	}

	return Hash256(lamportPk)
}

func derivePath(sk PrivateKey, path []int) PrivateKey {
	for _, index := range path {
		sk = DeriveChildSk(sk, index)
	}
	return sk
}

func DeriveChildSk(parentSk PrivateKey, index int) PrivateKey {
	lamportPk := parentSkToLamportPk(parentSk, index)
	return KeyGen(lamportPk)
}

func Hash256(m []byte) []byte {
	hash := sha256.Sum256(m)
	return hash[:]
}

// Ref: https://github.com/Chia-Network/bls-signatures/blob/53243db501e1e9f5d031970da728efb1873f6c81/python-impl/hd_keys.py#L49
func DeriveChildSkUnhardened(parentSk PrivateKey, index uint32) PrivateKey {
	salt := make([]byte, 4)
	binary.BigEndian.PutUint32(salt, index)

	// h = hash256(bytes(parent_sk.get_g1()) + index.to_bytes(4, "big"))
	hash := Hash256(append(parentSk.GetPublicKey().Bytes(), salt...))

	// bls.PrivateKey.aggregate([PrivateKey.from_bytes(h), parent_sk])
	sum := new(big.Int).Add(new(big.Int).SetBytes(hash), new(big.Int).SetBytes(parentSk.Bytes()))
	bytes := new(big.Int).Mod(sum, bls12381.NewG1().Q()).Bytes()

	return KeyFromBytes(bytes)
}

// To make keys more secure, choose path len value of at least 4
// ex: []int{44, 8444, 2, varyingIndex}
func DerivePathUnhardened(sk PrivateKey, path []uint32) PrivateKey {
	for _, index := range path {
		sk = DeriveChildSkUnhardened(sk, index)
	}
	return sk
}
