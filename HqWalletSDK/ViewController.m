//
//  ViewController.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import "ViewController.h"
#import <CommonCrypto/CommonKeyDerivation.h>

#import "NSData+HqHash.h"
#import "NSString+HqString.h"
#import "HqWallet.h"
#import "HqBIP39.h"
#import "HqHDNode.h"

#import <openssl/bn.h>
#define HqLog(format, ...) printf("\n[%s] %s [第%d行] %s\n", __TIME__, __FUNCTION__, __LINE__, [[NSString stringWithFormat:format,##__VA_ARGS__] UTF8String]);

@interface ViewController ()

@property(nonatomic,strong) HqWallet *wallet;
@property(nonatomic,strong) HqBIP39 *bip39;


@end

@implementation ViewController

- (HqWallet *)wallet{
    if (!_wallet) {
        _wallet = [[HqWallet alloc] init];
    }
    return _wallet;
}
- (HqBIP39 *)bip39{
    if (!_bip39) {
        _bip39 = [[HqBIP39 alloc] init];
    }
    return _bip39;
}
- (void)testBN_mod_add{
    
    /*
     1-----privateKey==2443bfa0106bbf76ab9357609c1f6541c382206b0164dcfef7eb03dd0f6f47e6
     pri-----derivedPrivateKey==5ada99f9ed1f200692f74bbfdc22b4336cd66d7a63933519ebf5e782f8fdce6f
     2-----privateKey==7f1e5999fd8adf7d3e8aa3207842197530588de564f81218e3e0eb60086d1655
     */
    
    char *a_str = "2443bfa0106bbf76ab9357609c1f6541c382206b0164dcfef7eb03dd0f6f47e6";
    char *b_str = "5ada99f9ed1f200692f74bbfdc22b4336cd66d7a63933519ebf5e782f8fdce6f";
    //https://www.secg.org/sec2-v2.pdf
    //secp256k1  n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    char *m_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *r = BN_new();
    
    
    BN_hex2bn(&a, a_str);
    BN_hex2bn(&b, b_str);
    
    printf("-------------[(a + b)]------------------\n");
    BN_add(r, a, b);
    char *r_str = BN_bn2hex(r);
    printf("%s + %s = %s\n",a_str,b_str,r_str);
    
    
    
    printf("-------------[(a + b) mod m]------------------\n");
    BN_hex2bn(&m, m_str);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BN_mod_add(r, a, b, m, ctx);
    BN_CTX_end(ctx);
    
    r_str = BN_bn2hex(r);
    
    
    printf("(%s + %s) mod %s = %s\n",a_str,b_str,m_str,r_str);
    
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_free(r);
    BN_CTX_free(ctx);
    
    
}
- (void)testBigMutil{
    char *k = "1639a64754d9a34b779f6d66144311fd4f665d16e91bff4e97a932ef869d2c14";
    char *G = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    //    k = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    k = "f3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3";
    //0x198d0a5ee063c06f922b98362b7897027f72868a575b9132acbf8a5e12ceff824f021f6ba3567698650df84b3061622b146b6e65ed129135cefb42ea187fc8821b
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *r = BN_new();
    
    BN_hex2bn(&a, k);
    BN_hex2bn(&b, G);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    
    BN_mul(r, a, b, ctx);
    BN_CTX_end(ctx);
    
    char *r_str = BN_bn2hex(r);
    printf("r == %s\n",r_str);
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_CTX_free(ctx);
    
}
- (void)testBigNumber{
    
    char *a_str = "1";
    char *b_str = "3";
    char *m_str = "3";
    
    
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *r = BN_new();
    
    
    BN_dec2bn(&a, a_str);
    BN_dec2bn(&b, b_str);
    
    BN_add(r, a, b);
    char *r_str = BN_bn2dec(r);
    printf("%s + %s = %s\n",a_str,b_str,r_str);
    
    BN_dec2bn(&m, m_str);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BN_mod_add(r, a, b, m, ctx);
    BN_CTX_end(ctx);
    
    r_str = BN_bn2dec(r);
    
    
    printf("(%s + %s) mod %s = %s\n",a_str,b_str,m_str,r_str);
    
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_free(r);
    BN_CTX_free(ctx);
    
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
}
- (void)testSign{
    NSString *pri = @"2d085f036fbdc7bfef82904efc53f9157f9478d7f184a85c7883f3bc44f44505";
    NSData *msg = @"f3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3".hexToData;
    [self.wallet opensslSignData:msg privateKey:pri];
}

/*
 验证网址
 https://iancoleman.io/bip39/#english
 */
- (void)testHDWalletCoinType:(int)type{
    NSString *btcPath = @"m/44'/0'/0'/0/0";
    NSString *ethPath = @"m/44'/60'/0'/0/0";
    NSString *eosPath = @"m/44'/194'/0'/0/0";
    NSArray *coinPaths = @[btcPath,ethPath,eosPath];
    
    NSString *mnemonic = @"woman bleak rude public require airport pole dismiss test turkey nice length";
//    self.bip39.language = BIP39LanguageZhCN;
//    mnemonic = [self.bip39 generateMnemonic];
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
    
    NSArray *walletTypes = @[@"BTC",@"ETH",@"EOS"];
    
    HqLog(@"-------------------------[%@]-------------------------",walletTypes[type]);

    HqLog(@"mnemonic==%@",self.wallet.mnemonic);
    HqLog(@"prikey==%@",pri);
    HqLog(@"pubkey==%@",pub);
    switch (type) {
        case 0:
        {
            self.wallet.address = [self.wallet btcAddressWithPubKey:pub];
            self.wallet.wifPrivatekey = [self.wallet btcWIFPrivatekey:pri compressed:YES];
            HqLog(@"btc_privatekey==%@",pri);
            HqLog(@"btc_WIFPrivatekey==%@",self.wallet.wifPrivatekey);
            HqLog(@"btc_address==%@",self.wallet.address);
            
        }
            break;
            
        case 1:
        {
            self.wallet.address = [self.wallet btcAddressWithPubKey:pub];
            self.wallet.wifPrivatekey = [self.wallet btcWIFPrivatekey:pri compressed:YES];
            self.wallet.address = [self.wallet ethAddressWithPubKey:pub];
            HqLog(@"eth_address==%@",self.wallet.address);
        }
            break;
        case 2:
        {
            self.wallet.address = [self.wallet eosAddressWithPubKey:pub];
            self.wallet.wifPrivatekey = [self.wallet eosWIFPrivatekey:pri];
            HqLog(@"eos_WIFPrivatekey==%@",self.wallet.wifPrivatekey);
            HqLog(@"eos_address==%@",self.wallet.address);
            
        }
            break;
        default:
            break;
    }
    
}
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    [super touchesEnded:touches withEvent:event];
    
    for (int i = 0; i<3; i++) {
        [self testHDWalletCoinType:i];
    }
    
}



@end
