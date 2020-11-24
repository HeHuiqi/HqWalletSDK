# HqWalletSDK

支持BTC、ETH、EOS三种链的HD钱包SDK
* 纯OC开发
* HD钱包的基本功能
* 消息的签名以及签名（待区分链）
* 钱包基本属性：助记词、私钥、公钥、地址
* 支持自定义开发

# 基本使用,详见Demo
```
    NSString *btcPath = @"m/44'/0'/0'/0/0";
    NSString *ethPath = @"m/44'/60'/0'/0/0";
    NSString *eosPath = @"m/44'/194'/0'/0/0";
    NSArray *coinPaths = @[btcPath,ethPath,eosPath];
    
    NSString *mnemonic = @"woman bleak rude public require airport pole dismiss test turkey nice length";
    NSString *saltPs = @"";
    NSData *seed = [self.bip39 mnemonicToSeed:mnemonic withPassphrase:saltPs];
    
    NSString *path = coinPaths[type];
    
    HqHDNode *node = [HqHDNode initSeed:seed network:0];
    node = [node derivedKeyPath:path];
    NSString *pri = node.privateKey.dataToHex;
    NSString *pub = node.publicKey.dataToHex;
    self.wallet.privateKey = node.privateKey;
    self.wallet.privateKey = node.publicKey;
    self.wallet.mnemonic = mnemonic;
    self.wallet.saltPs = saltPs;

```

# Demo 对应日志
```
[12:03:46] -[ViewController testHDWalletCoinType:] [第196行] -------------------------[BTC]-------------------------

[12:03:46] -[ViewController testHDWalletCoinType:] [第198行] mnemonic==woman bleak rude public require airport pole dismiss test turkey nice length

[12:03:46] -[ViewController testHDWalletCoinType:] [第199行] prikey==94d0173ae3c54f7f5061380497da77ad5c861ec434058086fafb29f0d25b4f50

[12:03:46] -[ViewController testHDWalletCoinType:] [第200行] pubkey==03d564be656e4e3a4522b89b7ec9c564a8ec69a8c484317860e47b30313ec04aca

[12:03:46] -[ViewController testHDWalletCoinType:] [第206行] btc_privatekey==94d0173ae3c54f7f5061380497da77ad5c861ec434058086fafb29f0d25b4f50

[12:03:46] -[ViewController testHDWalletCoinType:] [第207行] btc_WIFPrivatekey==L2Cz1AZtJ6yDXZ2cpoa7keQHi5tE5MSrdaB6bkSmyfbaGmHKra5s

[12:03:46] -[ViewController testHDWalletCoinType:] [第208行] btc_address==13HQnsnKPPat8YdTZsAhKn3hiYQKyYZSTj

[12:03:46] -[ViewController testHDWalletCoinType:] [第196行] -------------------------[ETH]-------------------------

[12:03:46] -[ViewController testHDWalletCoinType:] [第198行] mnemonic==woman bleak rude public require airport pole dismiss test turkey nice length

[12:03:46] -[ViewController testHDWalletCoinType:] [第199行] prikey==e0fd51bd46020f7dfc41f8e4ee8a26ba087d44a8e80c86c957d46dca9e6863e5

[12:03:46] -[ViewController testHDWalletCoinType:] [第200行] pubkey==0280e99f5dbab5f644e4edd37760505c5de88650d0488045acc8fe605783a9f7f5

[12:03:46] -[ViewController testHDWalletCoinType:] [第218行] eth_address==571db4b0663112c768e5931e59cbec3287fd8cb0

[12:03:46] -[ViewController testHDWalletCoinType:] [第196行] -------------------------[EOS]-------------------------

[12:03:46] -[ViewController testHDWalletCoinType:] [第198行] mnemonic==woman bleak rude public require airport pole dismiss test turkey nice length

[12:03:46] -[ViewController testHDWalletCoinType:] [第199行] prikey==bf65eae3fc3916ef0e417c7757ae57854dae27ace06b5960f123ccb5359e93ee

[12:03:46] -[ViewController testHDWalletCoinType:] [第200行] pubkey==025218b0edbd9153e99794b35c5f5318f946926157776c9146f33235f6f01c37d2

[12:03:46] -[ViewController testHDWalletCoinType:] [第225行] eos_WIFPrivatekey==5KGab9GygGUkTWVPgaPBbKjpoAj6azeCBfthJpUgi63kPM5peJX

[12:03:46] -[ViewController testHDWalletCoinType:] [第226行] eos_address==EOS5WePzeRXVvtkpnkJAdsoqdGa7aGjpkU728hADhLP3ctJjCF7KX

```

# 在线验证
[Mnemonic Code Converter](https://iancoleman.io/bip39/#english)
