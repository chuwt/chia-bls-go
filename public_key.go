package bls

import (
	bls12381 "github.com/kilic/bls12-381"
	"math/big"
)

type PublicKey struct {
	value *bls12381.PointG1
}

func NewPublicKey(data []byte) (PublicKey, error) {
	value, err := bls12381.NewG1().FromCompressed(data)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{
		value: value,
	}, nil
}

func (pk PublicKey) FingerPrint() string {
	return new(big.Int).SetBytes(Hash256(bls12381.NewG1().ToCompressed(pk.value))[:4]).String()
}

func (pk PublicKey) ToBytes() []byte {
	return bls12381.NewG1().ToCompressed(pk.value)
}

func (pk PublicKey) ToG1() *bls12381.PointG1 {
	return pk.value
}

func (pk PublicKey) Add(key PublicKey) PublicKey {
	g1 := bls12381.NewG1()
	return PublicKey{
		value: g1.Add(g1.New(), pk.value, key.ToG1()),
	}
}
