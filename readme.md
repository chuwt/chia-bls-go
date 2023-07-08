# chia-bls-go
- go版本chia签名, 参考python-impl实现部分功能，并非bls的完全实现

## Bug fix
- **2023/07/08** Thanks for [**goomario**](https://github.com/goomario)'s [report](https://github.com/chuwt/chia-bls-go/issues/7),
a bug was fixed!
  - This bug was caused by the wrong use of `big.Int.Bytes()`, it should be replaced with `big.Int.FillBytes()`

## 主要功能
- 生成私钥
  - 助记词
  - seed
  - hexString
  - bytes
- 签名
- 验签
- 多签
- 多签验证

## 安装说明
```
go get github.com/chuwt/chia-bls-go
```

## 使用说明
### 加载私钥
1. 助记词加载
```
func KeyGenWithMnemonic(mnemonic, password string) PrivateKey
```
2. hex string加载
```
func KeyFromHexString(key string) (PrivateKey, error)
```
3. bytes加载
```
func KeyFromHexString(key string) (PrivateKey, error)
```
### 私钥
1. 生成bytes
```
func (key PrivateKey) Bytes() []byte
```
2. 生成hex string
```
func (key PrivateKey) Hex() string
```
3. 派生farmerSk
```
func (key PrivateKey) FarmerSk() PrivateKey
```
4. 派生poolSk
```
func (key PrivateKey) PoolSk() PrivateKey 
```
5. 派生walletSk
```
func (key PrivateKey) WalletSk(index int) PrivateKey
```
6. 派生localSk
```
func (key PrivateKey) LocalSk() PrivateKey
```
7. 生成SyntheticSk
```
func (key PrivateKey) SyntheticSk(hiddenPuzzleHash []byte) PrivateKey
```
8. 生成公钥
```
func (key PrivateKey) GetPublicKey() PublicKey
```

### 公钥
1. 生成指纹(fingerprint)
```
func (key PublicKey) FingerPrint() string
```
2. 生成bytes
```
func (key PublicKey) Bytes() []byte
```
3. 生成hex string
```
func (key PublicKey) Hex() string
```

### 签名
1. 签名
```
func (asm *AugSchemeMPL) Sign(sk PrivateKey, message []byte)
```
2. 验证
```
func (asm *AugSchemeMPL) Verify(pk PublicKey, message []byte, sig []byte) bool
```
3. 多签
```
// 将多个签名联合在一起
func (asm *AugSchemeMPL) Aggregate(signatures ...[]byte) ([]byte, error)
```
4. 多签验证
```
// 公钥数组，原始信息数组，多签返回的数据
func (asm *AugSchemeMPL) AggregateVerify(pks [][]byte, messages [][]byte, sig []byte) bool
```
5. 前置公钥签名
```
// 前置公钥签名
SignWithPrependPK(sk PrivateKey, prependPK PublicKey, message []byte)
```