package bls

import (
	"encoding/hex"
	"testing"
)

func TestSign(t *testing.T) {
	asm := new(AugSchemeMPL)

	sk := KeyGen(testSeed)

	sign := asm.Sign(sk, []byte("chuwt"))
	t.Log("signedMsg:", hex.EncodeToString(sign))

	t.Log("verify:", asm.Verify(sk.GetPublicKey(), []byte("chuwt"), sign))
}

func TestAggregate(t *testing.T) {
	asm := new(AugSchemeMPL)

	masterSk := KeyGen(testSeed)

	farmerSk := masterSk.FarmerSk()
	farmerPk := farmerSk.GetPublicKey()

	poolSk := masterSk.PoolSk()
	poolPk := poolSk.GetPublicKey()

	// 签名
	sig1 := asm.Sign(farmerSk, []byte("chuwt1"))
	sig2 := asm.Sign(poolSk, []byte("chuwt2"))
	t.Log("sig1:", hex.EncodeToString(sig1))
	t.Log("sig2:", hex.EncodeToString(sig2))
	aggSig, err := asm.Aggregate(sig1, sig2)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("Aggregate:", hex.EncodeToString(aggSig))

	// 多签验证
	t.Log("AggregateVerify:", asm.AggregateVerify(
		[][]byte{
			farmerPk.Bytes(),
			poolPk.Bytes(),
		},
		[][]byte{
			[]byte("chuwt1"),
			[]byte("chuwt2"),
		},
		aggSig,
	))
}
