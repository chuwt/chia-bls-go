package bls

import (
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
)

type PrivateKey struct {
	value *big.Int
}

func (pk PrivateKey) GetPublicKey() PublicKey {
	g1 := bls12381.NewG1()
	return PublicKey{
		value: g1.MulScalar(g1.New(), G1Generator(), bls12381.NewFr().FromBytes(pk.value.Bytes())),
	}
}

func (pk PrivateKey) Bytes() []byte {
	return pk.value.Bytes()
}

func (pk PrivateKey) FarmerSk() PrivateKey {
	return derivePath(pk, []int{12381, 8444, 0, 0})
}

func (pk PrivateKey) PoolSk() PrivateKey {
	return derivePath(pk, []int{12381, 8444, 1, 0})
}

func (pk PrivateKey) WalletSk(index int) PrivateKey {
	return derivePath(pk, []int{12381, 8444, 2, index})
}

func (pk PrivateKey) LocalSk() PrivateKey {
	return derivePath(pk, []int{12381, 8444, 3, 0})
}
