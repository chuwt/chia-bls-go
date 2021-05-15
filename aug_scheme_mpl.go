package bls

import (
	"errors"
	bls12381 "github.com/kilic/bls12-381"
)

var (
	AugSchemeDst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_")
)

type AugSchemeMPL struct{}

// Sign 签名
func (asm *AugSchemeMPL) Sign(sk PrivateKey, message []byte) []byte {
	return bls12381.NewG2().ToCompressed(coreSignMpl(sk, message, AugSchemeDst))
}

// Verify 验证
func (asm *AugSchemeMPL) Verify(pk PublicKey, message []byte, sig []byte) bool {
	return coreVerifyMpl(
		pk,
		append(pk.ToBytes(), message...),
		sig,
		AugSchemeDst,
	)
}

// Aggregate 多签
func (asm *AugSchemeMPL) Aggregate(signatures ...[]byte) ([]byte, error) {
	return coreAggregateMpl(signatures...)
}

// AggregateVerify 多签验证
func (asm *AugSchemeMPL) AggregateVerify(pks [][]byte, messages [][]byte, sig []byte) bool {
	return coreAggregateVerify(pks, messages, sig, AugSchemeDst)
}

func coreSignMpl(sk PrivateKey, message, dst []byte) *bls12381.PointG2 {
	pk := sk.GetPublicKey()

	g2Map := bls12381.NewG2()

	q, _ := g2Map.HashToCurve(append(pk.ToBytes(), message...), dst)

	return g2Map.MulScalar(g2Map.New(), q, bls12381.NewFr().FromBytes(sk.ToBytes()))
}

func coreVerifyMpl(pk PublicKey, message []byte, sig, dst []byte) bool {

	g2Map := bls12381.NewG2()
	q, _ := g2Map.HashToCurve(message, dst)

	// 校验
	signature, err := bls12381.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12381.NewEngine()

	g1Neg := new(bls12381.PointG1)
	g1Neg = bls12381.NewG1().Neg(g1Neg, G1Generator())

	engine = engine.AddPair(pk.ToG1(), q)
	engine = engine.AddPair(g1Neg, signature)

	return engine.Check()
}

func coreAggregateMpl(signatures ...[]byte) ([]byte, error) {
	if len(signatures) < 1 {
		return nil, errors.New("Must aggregate at least 1 signature ")
	}

	newG2 := bls12381.NewG2()
	aggSig := newG2.New()

	for _, sig := range signatures {
		g2, err := bls12381.NewG2().FromCompressed(sig)
		if err != nil {
			return nil, err
		}
		aggSig = bls12381.NewG2().Add(newG2.New(), aggSig, g2)
	}

	return bls12381.NewG2().ToCompressed(aggSig), nil
}

func coreAggregateVerify(pks, messages [][]byte, sig, dst []byte) bool {
	pksLen := len(pks)

	if pksLen != len(messages) && pksLen < 1 {
		return false
	}

	g1Neg := new(bls12381.PointG1)
	g1Neg = bls12381.NewG1().Neg(g1Neg, G1Generator())

	signature, err := bls12381.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12381.NewEngine()
	engine.AddPair(g1Neg, signature)

	for index, pk := range pks {
		p, err := bls12381.NewG1().FromCompressed(pk)
		if err != nil {
			return false
		}

		g2Map := bls12381.NewG2()
		q, err := g2Map.HashToCurve(append(pks[index], messages[index]...), dst)
		if err != nil {
			return false
		}

		engine.AddPair(p, q)
	}
	return engine.Check()
}
