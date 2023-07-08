package bls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	testSeed, _ = hex.DecodeString("" +
		"76f3109f1a2142fdefcc6a666d3f321b37ce9690d28103ccbb1a654af2c0a469" +
		"00aac14fab9f0ce4851cf1a1fe8beaf7d34c9ceb008849d5b7e9bc78ef0ec649")

	testMnemonic = "" +
		"media spike luggage ramp famous gentle social wolf sing raven student involve " +
		"poverty team capital inspire lumber hat park nose effort still fatigue supply"

	testHexString = "6971ac2114952dfa1e4c8e8053308aa115bd75aa890a7d82a45718f334329191"
)

/*
Fingerprint: 563730848

master private key: 6971ac2114952dfa1e4c8e8053308aa115bd75aa890a7d82a45718f334329191

master public key: b2d709611a67e5224cbe9010739b138356e88bbdc4b91a833a489213bab9ad39cfee9c93e0fc3c70a0c4a6b6c5ada8b5

Farmer public key (m/12381/8444/0/0): b69b74794fa16c4569af42401615948094ad076795627d88f08e5f1626ec3e2dda47376db481dd3ecdf0585b960b80cf

Pool public key (m/12381/8444/1/0): 8b417b4310ecb7fd68e8c39e0fa0e334edd3c8c93eca9985a3f398846f9429142993196416199436718f3ec26609e618
*/

func TestSyntheticSk(t *testing.T) {
	// 需要注意公钥对应的index是0，目前暂时只支持0，后面可以添加检索
	masterSk, _ := KeyFromHexString(testHexString)

	walletSK := masterSk.WalletSk(0)
	t.Log(walletSK.Hex())

	// key is a wallet sk, not master sk
	syntheticSk := walletSK.SyntheticSk(Hidden)

	t.Log(syntheticSk.Hex())
}

func TestWalletIndex(t *testing.T) {
	masterSk, _ := KeyFromHexString(testHexString)
	for i := 0; i < 10; i++ {
		walletSk := masterSk.WalletSk(i)
		walletPk := walletSk.GetPublicKey()
		t.Log(i, walletPk.Hex(), walletSk.Hex())
	}
}

func TestBls(t *testing.T) {

	masterSk := KeyGen(testSeed)
	masterSkWithMnemonic := KeyGenWithMnemonic(testMnemonic, "")

	t.Log("sk compare:", bytes.Compare(masterSk.Bytes(), masterSkWithMnemonic.Bytes()))

	masterPk := masterSk.GetPublicKey()

	t.Log("masterSk:", masterSk.Hex())
	t.Log("masterPk:", masterPk.Hex())
	t.Log("fingerprint:", masterPk.FingerPrint())

	t.Log("")

	farmerSk := masterSk.FarmerSk()
	farmerPk := farmerSk.GetPublicKey()
	t.Log("farmerSk:", farmerSk.Hex())
	t.Log("farmerPk:", farmerPk.Hex())

	t.Log("")

	poolSk := masterSk.PoolSk()
	poolPk := poolSk.GetPublicKey()
	t.Log("poolSk:", poolSk.Hex())
	t.Log("poolPk:", poolPk.Hex())
}

func TestKeyGen(t *testing.T) {
	sk, err := KeyFromHexString(testHexString)
	if err != nil {
		t.Error(err)
		return
	}
	key := sk.GetPublicKey()
	t.Log("pk:", key.Hex()) // b2d709611a67e5224cbe9010739b138356e88bbdc4b91a833a489213bab9ad39cfee9c93e0fc3c70a0c4a6b6c5ada8b5
}

func TestPublicKeyAdd(t *testing.T) {
	masterSk := KeyGen(testSeed)

	farmerSk := masterSk.FarmerSk()
	localSk := masterSk.LocalSk()

	farmerPk := farmerSk.GetPublicKey()
	localPk := localSk.GetPublicKey()

	aggKey := farmerPk.
		Add(localPk)
	// will be 8e0d77cc057663bb70d834acfa584117232f3ce0e1519a0b927bce626bdd7131a6896b02b8ad80a1dec3eddcbc1ec471
	t.Log(aggKey.Hex())
}

// https://github.com/chuwt/chia-bls-go/issues/7
func TestIssue7(t *testing.T) {
	seed, _ := hex.DecodeString("16e68a14f0728688d62cf6996fc42aa1e1d0212d3d6c530335d90718f220aa42556d33b6a855afcbd1b3e5144a29030a1b0eed3ce325b9f8bf334051b3e2fc8d")
	seedFarmerSK := "0x72819845fad63e8b42399abd86d7175fa6d7a984a992e743936858c1e6753b9b"

	pk := KeyGen(seed)
	farmerKey := pk.FarmerSk()

	t.Log("farmer sk compare:", farmerKey.Hex() == seedFarmerSK)
}
