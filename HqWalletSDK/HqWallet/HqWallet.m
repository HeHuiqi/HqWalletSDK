//
//  HqWallet.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//sha3
//https://github.com/brainhub/SHA3IUF
#import "HqWallet.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import "NSData+HqHash.h"
#import "NSString+HqString.h"
#import <openssl/crypto.h>
#import <openssl/ecdsa.h>
#import <openssl/evp.h>
#import "sha3.h"
#import <secp256k1.h>
#import <secp256k1_recovery.h>
#define HASH256_SIZE (32)

@implementation HqWallet

void hq_print_key(const uint8_t *key,long key_len){
    printf("key_len:%ld\n",key_len);
    for (int i = 0; i<key_len; i++) {
        printf("%0x",key[i]);
    }
    printf("\n");
}
char * hq_format_key(const uint8_t *key,long key_len){
    char *result = calloc(key_len,sizeof(char *));
    char hex[4];//一个整型4个字节
    for (int i = 0; i<key_len; i++) {
        sprintf(hex, "%x", key[i]);
        result = strcat(result, hex);
    }
    printf("result=%s\n",result);
    free(result);
    return result;
}
EC_KEY *hq_ec_new_keypair(const uint8_t *priv_bytes,bool compressed) {
    EC_KEY *key;
    BIGNUM *priv;
    BN_CTX *ctx;
    const EC_GROUP *group;
    EC_POINT *pub;
    
    /* init empty OpenSSL EC keypair */
    
    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    /* set private key through BIGNUM */
    
    priv = BN_new();
    BN_bin2bn(priv_bytes, 32, priv);
    EC_KEY_set_private_key(key, priv);
    
    /* derive public key from private key and group */
    
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    
    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
    EC_KEY_set_conv_form(key, compressed ? POINT_CONVERSION_COMPRESSED:POINT_CONVERSION_UNCOMPRESSED);
    
    EC_KEY_set_public_key(key, pub);
    //    EC_KEY_print_fp(stdout, key, 0);
    
    /* release resources */
    
    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(priv);
    
    return key;
}

- (void)testMethod{
    NSLog(@"钱包------\n");
    [self testWallet];
    NSLog(@"签名------\n");
    [self testSign];
}
- (void)testWallet{
    //    NSData *random = [NSData randomWithSize:32];
    //    NSLog(@"random:%@",random.dataToHex);
    //    NSString *prikey = random.dataToHex;
    BOOL compress = NO;
    NSString *prikey = @"";
    //随机生成一个私钥
    //    prikey = @"1639a64754d9a34b779f6d66144311fd4f665d16e91bff4e97a932ef869d2c14";
    prikey = @"7870f174872b5a60af8072487c9e50a11ce6ce780499bbc8a4404a7b9cf99aeb";
    [self btcWIFPrivatekey:prikey compressed:compress];
    NSData *pubData = [self priToPub:prikey compressed:compress];
    NSString *pubHex = pubData.dataToHex;
    [self btcAddressWithPubKey:pubHex];
    NSString *ethPubHex = [pubData.dataToHex substringFromIndex:2];
    [self ethAddressWithPubKey:ethPubHex];
    
}

- (void)testSign{
    NSData *msgData = @"f3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3".hexToData;
    NSString *pri = @"1639a64754d9a34b779f6d66144311fd4f665d16e91bff4e97a932ef869d2c14";
    pri = @"7870f174872b5a60af8072487c9e50a11ce6ce780499bbc8a4404a7b9cf99aeb";
    NSData *pubData = @"048f6daad48cf29cfddb86c6e65e600486c63e64ae66011073b2e2e8787d9b169796a17fe811a5982fd5f4e375ac43d6b144421c081e31e051a171d082989d66b6".hexToData;
    NSData *signData = nil;
    //    signData = [self signHashMessage:msgData privateKey:pri.hexToData];
    NSData *recoverSignData = [self recoverSignHashMessage:msgData privateKey:pri.hexToData];
    signData = [recoverSignData subdataWithRange:NSMakeRange(0, 64)];
    [self verifySign:signData hashMessage:msgData pubKey:pubData];
    
}

#pragma mark - Wallet
- (NSString *)generateMnemonic{
    
    
    
    return nil;
}



- (NSData *)priToPub:(NSString *)pri compressed:(BOOL)compressed{
    const unsigned char *seckey = (const unsigned char *)pri.hexToData.bytes;
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey ;
    int res = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    if (res != 1) {
        return nil;
    }
    
    size_t outputlen = compressed ? 33:65;
    int compressFlag = compressed ? SECP256K1_EC_COMPRESSED:SECP256K1_EC_UNCOMPRESSED;
    
    unsigned char *output = calloc(outputlen, sizeof(char));
    secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &pubkey, compressFlag);
    NSData *pubData = [[NSData alloc] initWithBytes:output length:outputlen];
    NSLog(@"pubHex==%@",pubData.dataToHex);
    secp256k1_context_destroy(ctx);
    
    //    secp256k1_ec_privkey_tweak_add
    
    return  pubData;
}
//https://segmentfault.com/a/1190000013176420?utm_source=channel-hottest
//http://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/
//https://github.com/keeshux/basic-blockchain-programming/

- (NSData *)opensslPriToPub:(NSString *)pri compressed:(BOOL)compressed{
    NSData *secret =  pri.hexToData;
    unsigned char *pp;
    int len;
    
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv = BN_new();
    // binary  to BIGNUM
    BN_bin2bn(secret.bytes, 32, priv);
    //设置私钥
    EC_KEY_set_private_key(ec_key, priv);
    //公钥推导
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub = EC_POINT_new(group);
    //相乘
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(ec_key, pub);
    
    EC_KEY_set_conv_form(ec_key, compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    
    if (pub) EC_POINT_free(pub);
    BN_clear_free(priv);
    if (ctx) BN_CTX_end(ctx);
    if (ctx) BN_CTX_free(ctx);
    
    //打印ec_key
    EC_KEY_print_fp(stdout, ec_key, 0);
    
    const BIGNUM *mypriv = EC_KEY_get0_private_key(ec_key);
    NSData *priKeyesult = [[NSMutableData alloc] initWithLength:32];
    // BIGNUM to binary
    BN_bn2bin(mypriv,  (unsigned char *)priKeyesult.bytes);
    
    
    unsigned char pubBuf[1024]={0};
    pp = pubBuf;
    len  = i2o_ECPublicKey(ec_key,&pp);
    if (!len) {
        EC_KEY_free(ec_key);
        return nil;
    }
    EC_KEY_free(ec_key);
    NSData *pubData = [[NSData alloc] initWithBytes:pubBuf length:len];
    return  pubData;
    
}

- (NSString *)btcWIFPrivatekey:(NSString *)prikey compressed:(BOOL)compressed{
    
    NSString *prifix = @"80";
    NSString *subfix = compressed ? @"01":@"";
    NSString *pri  = [NSString stringWithFormat:@"%@%@%@",prifix,prikey,subfix];
    NSData *priData = pri.hexToData;
    NSData *sha2 = priData.SHA256_2;
    NSMutableData *privateData = [[NSMutableData alloc] initWithData:priData];
    //4个字节checksum
    NSData *checksum = [sha2 subdataWithRange:NSMakeRange(0, 4)];
    [privateData appendData:checksum];
    
    NSString *wifPrivateKey = [NSString base58WithData:privateData];
    //    NSLog(@"wifPrivateKey==%@",wifPrivateKey);
    return wifPrivateKey;
}
- (NSString *)eosWIFPrivatekey:(NSString *)prikey{
    
    NSString *prifix = @"80";
    NSString *pri  = [NSString stringWithFormat:@"%@%@",prifix,prikey];
    NSData *priData = pri.hexToData;
    NSData *sha2 = priData.SHA256_2;
    NSMutableData *privateData = [[NSMutableData alloc] initWithData:priData];
    //4个字节checksum
    NSData *checksum = [sha2 subdataWithRange:NSMakeRange(0, 4)];
    [privateData appendData:checksum];
    
    NSString *wifPrivateKey = [NSString base58WithData:privateData];
    //    NSLog(@"wifPrivateKey==%@",wifPrivateKey);
    return wifPrivateKey;
}

/**
 //btc 地址如何生成
 https://www.jianshu.com/p/954e143e97d2
 */
- (NSString *)btcAddressWithPubKey:(NSString *)pubKey{
    NSData *pubData = pubKey.hexToData;
    NSData *hash160 = pubData.hash160;
    
    //    NSLog(@"hash160==%@",hash160.dataToHex);
    
    NSMutableData *adrData = [[NSMutableData alloc] init];
    
    char pp1[] = {0x00};//主网地址前缀00
    NSData *prfix = [[NSData alloc] initWithBytes:pp1 length:1];
    [adrData appendData:prfix];
    [adrData appendData:hash160];
    
    NSData *sha2data = adrData.SHA256_2;
    NSData *checksum = [sha2data subdataWithRange:NSMakeRange(0, 4)];
    NSMutableData *result = [[NSMutableData alloc] initWithData:adrData];
    [result appendData:checksum];
    
    NSString *bs58Address = [NSString base58WithData:result];
    //    NSLog(@"bs58Address:%@",bs58Address);
    return  bs58Address;
    
}

- (NSString *)eosAddressWithPubKey:(NSString *)pubKey{
    NSData *pubData = pubKey.hexToData;
    NSData *ripemd160 = pubData.RMD160;
    
//    NSLog(@"ripemd160==%@",ripemd160.dataToHex);
 
    NSMutableData *result = [[NSMutableData alloc] initWithData:pubData];

    NSData *checksum = [ripemd160 subdataWithRange:NSMakeRange(0, 4)];
    [result appendData:checksum];
    
    NSString *bs58Address = [NSString base58WithData:result];
    
    return  [@"EOS" stringByAppendingString:bs58Address];
    
}


/**
 https://www.jianshu.com/p/d3837398f69c
 以太坊生成地址的方式跟比特币比较类似，也是 私钥 -> 公钥 -> 地址，以太坊只是在公钥 -> 地址做了简化。
 以太坊使用Secp256k1椭圆曲线得到私钥、公钥，比特币使用的也是相同的椭圆曲线算法。
 得到公钥后，对公钥做Keccak-256哈希运算，然后取最后的40位(后20字节)16进制字符，得到的就是以太坊地址
 */
//这里的公钥为非压缩格式且没有04前缀

- (void)test_pressed_pubkey_combinePub {
    secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    
    NSData *pubData = @"048f6daad48cf29cfddb86c6e65e600486c63e64ae66011073b2e2e8787d9b169796a17fe811a5982fd5f4e375ac43d6b144421c081e31e051a171d082989d66b6".hexToData;
    //    pubData = @"02cc5d99b6fefa10d62103d6715d909ae22372c9a6ebd96462580a0a2a4d7d989c".hexToData;
    
    const unsigned char *inputPubKey = pubData.bytes;
    secp256k1_pubkey inKey;
    
    int res = 0;
    res = secp256k1_ec_pubkey_parse(context, &inKey, inputPubKey, pubData.length);
    NSLog(@"1----res==%@",@(res));
    
    //    const secp256k1_pubkey * const *pubnonces
    /*
     *  In:     ins:        pointer to array of pointers to public keys (cannot be NULL)
     *          n:          the number of public keys to add together (must be at least 1)
     */
    
    const secp256k1_pubkey* pubnonces[1];
    pubnonces[0] = &inKey;
    
    secp256k1_pubkey outKey;
    res = secp256k1_ec_pubkey_combine(context, &outKey, pubnonces, 1);
    //    res = secp256k1_ec_pubkey_negate(context, &inKey);
    //
    NSLog(@"2----res==%@",@(res));
    //    BOOL compressed = NO;
    BOOL compressed = pubData.length == 33 ? YES:NO;
    
    size_t outputlen = compressed ? 33:65;
    unsigned char *output  = calloc(outputlen,sizeof(char));
    res = secp256k1_ec_pubkey_serialize(context, output, &outputlen, &outKey, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    NSLog(@"3----res==%@,outputlen=%@",@(res),@(outputlen));
    
    NSString *pub = [[NSData alloc] initWithBytes:output length:outputlen].dataToHex;
    NSLog(@"4----pub==%@",pub);
    free(output);
    
    
    [self ethAddressWithPubKey:pub];
    
}


- (NSData *)pubkey_combine:(NSData *)pubkeyData {
    
    if (pubkeyData.length == 65) {
        return pubkeyData;
    }
    if (pubkeyData.length != 33) {
        return nil;
    }
    secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    const unsigned char *inputPubKey = pubkeyData.bytes;
    secp256k1_pubkey inKey;
    
    int res = 0;
    res = secp256k1_ec_pubkey_parse(context, &inKey, inputPubKey, 33);
    //    NSLog(@"1----res==%@",@(res));
    
    const secp256k1_pubkey* pubnonces[1];
    pubnonces[0] = &inKey;
    
    secp256k1_pubkey outKey;
    res = secp256k1_ec_pubkey_combine(context, &outKey, pubnonces, 1);
    //    res = secp256k1_ec_pubkey_negate(context, &inKey);
    //
    //    NSLog(@"2----res==%@",@(res));
    BOOL compressed = NO;
    size_t outputlen = compressed ? 33:65;
    unsigned char *output  = calloc(outputlen,sizeof(char));
    res = secp256k1_ec_pubkey_serialize(context, output, &outputlen, &outKey, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    //    NSLog(@"3----res==%@,outputlen=%@",@(res),@(outputlen));
    
    NSData *pub = [[NSData alloc] initWithBytes:output length:outputlen];
    //    NSLog(@"4----pub==%@",pub);
    free(output);
    secp256k1_context_destroy(context);
    return  pub;
    
}

- (NSString *)ethAddressWithPubKey:(NSString *)pubKey{
    
    //        pubKey = @"04cc5d99b6fefa10d62103d6715d909ae22372c9a6ebd96462580a0a2a4d7d989c5ba7258078011c87b32c5f9457df228d047c2d26201c9e2bfac0c84c0d7096ae";
    NSData *pubData = pubKey.hexToData;
    pubData = [self pubkey_combine:pubData];
    if (pubData.length == 65) {
        pubData = [pubData subdataWithRange:NSMakeRange(1, 64)];
    }else{
        return nil;
    }
    NSString *result = pubData.keccak256.dataToHex;
    //    NSLog(@"keccak256==%@",result);
    if (result.length > 40) {
        NSString *eth_address = [result substringFromIndex:result.length - 40];
        //        NSLog(@"eth_address==%@",eth_address);
        return eth_address;
    }
    return  @"";
    
}


#pragma mark - Sign



- (NSData *)recoverSignHashMessage:(NSData *)hashMessage privateKey:(NSData *)privateKey{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_recoverable_signature signature;
    int res = secp256k1_ecdsa_sign_recoverable(ctx, &signature, hashMessage.bytes, privateKey.bytes, nil, nil);
    NSLog(@"secp256k1_ecdsa_sign_recoverable==%@",@(res));
    if (res != 1) {
        secp256k1_context_destroy(ctx);
        return nil;
    }
    unsigned char sig64[64] = { 0 };
    
    int v = -1;
    res = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,sig64,&v,&signature);
    NSLog(@"secp256k1_ecdsa_recoverable_signature_serialize_compact==%@",@(res));
    if (res != 1) {
        secp256k1_context_destroy(ctx);
        return nil;
    }
    NSMutableData *sig65Data = [[NSMutableData alloc] initWithBytes:sig64 length:65];
    NSLog(@"v==%@",@(v));
    if (v != -1) {
        v = v + 27;
        [sig65Data appendBytes:&v length:1];
    }
    NSLog(@"sig65Data.dataToHex==%@",sig65Data.dataToHex);
    /*
     secp256k1_ecdsa_signature sig;
     res = secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &signature);
     NSLog(@"secp256k1_ecdsa_recoverable_signature_convert==%@",@(res));
     
     unsigned char sig64_s[64] = { 0 };
     secp256k1_ecdsa_signature_serialize_compact(ctx,sig64_s, &sig);
     NSData *sig64Data = [[NSData alloc] initWithBytes:sig64 length:64];
     NSLog(@"sig64Data.dataToHex==%@",sig64Data.dataToHex);
     */
    secp256k1_context_destroy(ctx);
    return sig65Data;
    
    
}



- (NSData *)signHashMessage:(NSData *)hashMessage privateKey:(NSData *)privateKey {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_sign(ctx, &signature, hashMessage.bytes, privateKey.bytes, NULL, NULL);
    
    
    unsigned char sig_output64[64] = {};
    int res = secp256k1_ecdsa_signature_serialize_compact(ctx, sig_output64, &signature);
    NSLog(@"secp256k1_ecdsa_signature_serialize_compact==%@",@(res));
    
    
    NSData *signData = [[NSData alloc] initWithBytes:sig_output64 length:64];
    //    [self verifySign:signData hashMessage:hashMessage pubKey:pubData];
    secp256k1_context_destroy(ctx);
    
    
    return  signData;
    
}



//signData 经过message hash256()得到
- (BOOL)verifySign:(NSData *)signData hashMessage:(NSData *)hashMessage pubKey:(NSData *)pubKey{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    const unsigned char *input = pubKey.bytes;
    int res = secp256k1_ec_pubkey_parse(ctx, &pubkey, input, pubKey.length);
    NSLog(@"secp256k1_ec_pubkey_parse==%@",@(res));
    
    if (res != 1) {
        secp256k1_context_destroy(ctx);
        return NO;
    }
    if (signData.length != 64) {
        secp256k1_context_destroy(ctx);
        return  NO;
    }
    const unsigned char *input64 = (const unsigned char *)signData.bytes;
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_signature_parse_compact(ctx, &sig, input64);
    res = secp256k1_ecdsa_verify(ctx, &sig, hashMessage.bytes, &pubkey);
    NSLog(@"secp256k1_ecdsa_verify==%@",@(res));
    secp256k1_context_destroy(ctx);
    return NO;
}
- (NSData *)signHashMessage:(NSData *)hashMessage withPrivateKey:(NSData *)privateKey {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_signature normalizedSignature;
    secp256k1_ecdsa_sign(ctx, &signature, hashMessage.bytes, privateKey.bytes, NULL, NULL);
    
    size_t siglen = 74;
    NSMutableData *der = [NSMutableData dataWithLength:siglen];
    secp256k1_ecdsa_signature_serialize_der(ctx, der.mutableBytes, &siglen, &normalizedSignature);
    der.length = siglen;
    secp256k1_context_destroy(ctx);
    return der;
}
//每次签名都变化，原因待研究
- (NSString *)opensslSignData:(NSData *)data privateKey:(NSString *)privateKey{
    
    NSData *secret =  privateKey.hexToData;
    const unsigned char *dgst = (unsigned char *)data.bytes;
    int dgstLen = (int)data.length;
    EC_KEY *ec_key = hq_ec_new_keypair(secret.bytes,false);
    if (ec_key == NULL) {
        return  nil;
    }
    /*
     unsigned int siglen;
     int size = ECDSA_size(ec_key);
     unsigned char*sig;
     sig = calloc(size, sizeof(char));
     int ret = ECDSA_sign(0, dgst, dgstLen, sig, &siglen, ec_key);
     NSLog(@"ECDSA_sign_ret:%@", @(ret));
     NSData *sginData = [[NSData alloc] initWithBytes:sig length:size];
     NSLog(@"sginData==%@",sginData.dataToHex);
     ret = ECDSA_verify(0,dgst,dgstLen,sig,siglen,ec_key);
     NSLog(@"ECDSA_verify_ret:%@", @(ret));
     */
    
    ECDSA_SIG *signature = ECDSA_do_sign(dgst, dgstLen, ec_key);
    char *rhex = BN_bn2hex(signature->r);
    char *shex = BN_bn2hex(signature->s);
    NSLog(@"r:%s",rhex);
    NSLog(@"s:%s",shex);
    
    int ret = ECDSA_do_verify(dgst, dgstLen, signature, ec_key);
    NSLog(@"ECDSA_verify_ret:%@", @(ret));
    ECDSA_SIG_free(signature);
    
    EC_KEY_free(ec_key);
    
    return @"";
}

void bbp_print_hex(const char *label, const uint8_t *v, size_t len) {
    size_t i;
    
    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", v[i]);
    }
    printf("\n");
}

void tes_sigh(void){
    //    prikey：1639a64754d9a34b779f6d66144311fd4f665d16e91bff4e97a932ef869d2c14
    //    hashMessageData：f3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    const unsigned char *private_key = @"1639a64754d9a34b779f6d66144311fd4f665d16e91bff4e97a932ef869d2c14".hexToData.bytes;
    BIGNUM *priv_key =  BN_bin2bn(private_key, 32, BN_new());
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    BIGNUM *order = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP_get_order(group, order, ctx);
    EC_POINT *pub_key = EC_POINT_new(group);
    EC_POINT_mul(group, pub_key, priv_key, nil, nil, ctx);
    EC_KEY_set_private_key(eckey, priv_key);
    EC_KEY_set_public_key(eckey, pub_key);
    
//    EC_KEY_print_fp(stdout, eckey, 0);
    const unsigned char *hash = @"f3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3".hexToData.bytes;
    ECDSA_SIG *signature;
    signature = ECDSA_do_sign(hash, sizeof(hash), eckey);
    NSLog(@"hash==%@",[[NSData alloc] initWithBytes:hash length:32]);

    
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));
    
    
    /*
     priv_key = BN_bin2bn(private_key, private_key.bytesize, BN_new())
     
     group, order, ctx = EC_KEY_get0_group(eckey), BN_new(), BN_CTX_new()
     EC_GROUP_get_order(group, order, ctx)
     
     pub_key = EC_POINT_new(group)
     EC_POINT_mul(group, pub_key, priv_key, nil, nil, ctx)
     EC_KEY_set_private_key(eckey, priv_key)
     EC_KEY_set_public_key(eckey, pub_key)
     
     signature = ECDSA_do_sign(hash, hash.bytesize, eckey)
     
     BN_free(order)
     BN_CTX_free(ctx)
     EC_POINT_free(pub_key)
     BN_free(priv_key)
     EC_KEY_free(eckey)
     */
}
@end

/**
 钱包
 BTC偏好压缩格式，ETH偏好未压缩格式
 现在一般大部分用未压缩格式的
 prikey:7870f174872b5a60af8072487c9e50a11ce6ce780499bbc8a4404a7b9cf99aeb
 
 未压缩
 wifPrivateKey==5JjL6AiqNcvaSRLhuZEqmo57EsZdJt2uE1v2Yjs6N7REmkeigbN
 privateKey:7870f174872b5a60af8072487c9e50a11ce6ce780499bbc8a4404a7b9cf99aeb
 public_key_len:65
 publickey:048f6daad48cf29cfddb86c6e65e600486c63e64ae66011073b2e2e8787d9b169796a17fe811a5982fd5f4e375ac43d6b144421c081e31e051a171d082989d66b6
 hash160==eb2d9bc369b86d723109a480feef42435a60b4e7
 bs58Address:1NSWS1dV6717FqVcAfdydEmhD2sRh4TXR4
 keccak256==dd9f06947495b0fad2a2edbce924bbe9e55b81cee3b3de7b78f0b27882a2a0b2
 eth_address==e924bbe9e55b81cee3b3de7b78f0b27882a2a0b2
 
 压缩
 wifPrivateKey==L1FqFoueWRZUbCRyYyJ6GiM8YEB1FvFPWT33q6C6gBKynMSfiuLX
 privateKey:7870f174872b5a60af8072487c9e50a11ce6ce780499bbc8a4404a7b9cf99aeb
 public_key_len:33
 publickey:028f6daad48cf29cfddb86c6e65e600486c63e64ae66011073b2e2e8787d9b1697
 hash160==7d73d415fe9d42eb06ae4f69c59f70100e51969c
 bs58Address:1CSLDt7p1s4J6tDrZSwSRVYrGYqng3JDoC
 keccak256==c97fc64cb360b011d97a2ada1cdd7555b2d1127447c291bb64649be242b9bb90
 eth_address==1cdd7555b2d1127447c291bb64649be242b9bb90
 
 */

/**
 
 签名
 prikey：1639a64754d9a34b779f6d66144311fd4f665d16e91bff4e97a932ef869d2c14
 hashMessageData：0xf3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3
 recoverSignData：0x198d0a5ee063c06f922b98362b7897027f72868a575b9132acbf8a5e12ceff824f021f6ba3567698650df84b3061622b146b6e65ed129135cefb42ea187fc8821b
 
 prikey：7870f174872b5a60af8072487c9e50a11ce6ce780499bbc8a4404a7b9cf99aeb
 hashMessageData：0xf3ed7c9d5a5acb509d5d9fa8ae2df5893711439b8e4ee79b29fa8bd35fe70fc3
 recoverSignData：0xcf4de6b2eb13c5b2a4d58c2026cd057bbee9e53c6fc9886aa9b939350f20625a5ab19b22b1199328ad5939fa209b2952c220cf4a4dabaec12cfa3a1f43b1c4fd5a1b
 */

//    apology elegant door blur coconut zoo lawn trumpet expire lizard ship cruel
//    address=0x5b88bF5D0e6DC70B02e459C0127b53e2dAD4687D
