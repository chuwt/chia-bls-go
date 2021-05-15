# chia-bls-go
- go版本chia签名, 感谢[github.com/kurefm/gochia](https://github.com/kurefm/gochia)
这个项目给我的灵感，之前也准备根据python-implement进行重写，但是不知道bls签名如何实现，后面看到有
[github.com/kilic/bls12-381](github.com/kilic/bls12-381)这个项目，然后就愉快的实现了

## 主要功能
- 生成私钥
  - 助记词
  - seed
  - hexString
  - bytes
- 签名
- 验签
- 多签(WIP)
- 多签验证(WIP)
- 交易签名(WIP)

## 安装说明
```
go get github.com/chuwt/chia-bls-go
```

## 使用说明
```
暂时看test吧
```