//
//  NSData+HqHash.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import "NSData+HqHash.h"
#import <openssl/ripemd.h>
#import <openssl/bn.h>
#import <openssl/evp.h>
#import "sha3.h"
#import "NSString+HqString.h"

@implementation NSData (HqHash)

- (NSData *)SHA1 {
    NSMutableData *d = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];

    CC_SHA1(self.bytes, (CC_LONG) self.length, d.mutableBytes);

    return d;
}


- (NSData *)SHA256 {
    NSMutableData *d = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];

    CC_SHA256(self.bytes, (CC_LONG) self.length, d.mutableBytes);

    return d;
}

- (NSData *)SHA256_2 {
    NSMutableData *d = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];

    CC_SHA256(self.bytes, (CC_LONG) self.length, d.mutableBytes);
    CC_SHA256(d.bytes, (CC_LONG) d.length, d.mutableBytes);

    return d;
}

- (NSData *)RMD160 {
    
    NSMutableData *d = [[NSMutableData alloc] initWithCapacity:0];
    unsigned char md_value[RIPEMD160_DIGEST_LENGTH];
    unsigned int md_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    const EVP_MD *ripemd160 = EVP_ripemd160();
    EVP_DigestInit(ctx, ripemd160);
    EVP_DigestUpdate(ctx, self.bytes, self.length);
    EVP_DigestFinal(ctx, md_value, &md_len);
    EVP_MD_CTX_cleanup(ctx);
    [d appendBytes:md_value length:md_len];
//    EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)

    
//    NSMutableData *d = [NSMutableData dataWithLength:RIPEMD160_DIGEST_LENGTH];
    //openssl自带方法在以后的版本将废弃
//    RIPEMD160(self.bytes, self.length, d.mutableBytes);

    return d;
}

- (NSData *)hash160 {
    return self.SHA256.RMD160;
}
//在推导ETH地址时需要使用非压缩公钥才能得到正确的地址
- (NSData *)keccak256{
    sha3_context c;
    sha3_Init256(&c);
    uint8_t outBuf[32] = {0x0};
    uint8_t *bytes =(uint8_t *) self.bytes;
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, bytes, (int)self.length, outBuf, sizeof(outBuf));
    NSData *result = [[NSData alloc] initWithBytes:outBuf length:32];
    return result;
}
//https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Private_parent_key_rarr_private_child_key
- (NSData *)derivedPrivateKeyWithILData:(NSData *)iLData{
    if (self.length != 32 || iLData.length != 32) {
        return nil;
    }

    return  [self derivedKeyWithILData:iLData isPrivateKey:YES];
    
}
- (NSData *)derivedPublicKeyWithILData:(NSData *)iLData{
    if (self.length != 33 || iLData.length != 32) {
        return nil;
    }
    return  [self derivedKeyWithILData:iLData isPrivateKey:NO];

}
- (NSData *)derivedKeyWithILData:(NSData *)iLData isPrivateKey:(BOOL)isPrivateKey{
    
    const unsigned char *a_str = (const unsigned char *)self.bytes;
    const unsigned char *b_str = (const unsigned char *)iLData.bytes;
    char *r_str;
    //https://www.secg.org/sec2-v2.pdf
    //secp256k1  n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    char *m_n_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *m = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_bin2bn(a_str, (int)self.length, a);
    BN_bin2bn(b_str, (int)iLData.length, b);
    
    if (!isPrivateKey) {
//        printf("-------------[(a + b)]------------------\n");
        BN_add(r, a, b);
        r_str = BN_bn2hex(r);
    }else{
//        printf("-------------[(a + b) mod m]------------------\n");
        BN_hex2bn(&m, m_n_str);
        BN_CTX_start(ctx);
        BN_mod_add(r, a, b, m, ctx);
        BN_CTX_end(ctx);
        r_str = BN_bn2hex(r);
    }
    if (r_str == nil) {
        return nil;
    }
    NSString *result = [NSString stringWithFormat:@"%s",r_str];
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(m);
    BN_CTX_free(ctx);
    
    return  result.hexToData;
    
}


- (NSData *)reverse {
    NSUInteger l = self.length;
    NSMutableData *d = [NSMutableData dataWithLength:l];
    uint8_t *b1 = d.mutableBytes;
    const uint8_t *b2 = self.bytes;

    for (NSUInteger i = 0; i < l; i++) {
        b1[i] = b2[l - i - 1];
    }

    return d;
}


- (NSInteger)compare:(NSData *)data {
    
    BIGNUM *modulus = BN_bin2bn(self.bytes, (int)self.length, NULL);
    BIGNUM *exponent = BN_bin2bn(data.bytes, (int)data.length, NULL);
    int result = BN_cmp(modulus, exponent);
    BN_clear_free(modulus);
    BN_clear_free(exponent);
    return [NSNumber numberWithInt:result].integerValue;
}


+ (NSData *)randomWithBits:(NSInteger)bits {
    
    NSInteger size = bits/8;
    if (size  < 12 ) {
        assert("bits min is 128");
        return nil;
    }
    OSStatus sanityCheck = noErr;
    uint8_t *bytes = NULL;
    bytes = malloc(size * sizeof(uint8_t));
    memset((void *) bytes, 0x0, size);
    sanityCheck = SecRandomCopyBytes(kSecRandomDefault, size, bytes);
    if (sanityCheck == noErr) {
        return [NSData dataWithBytes:bytes length:size];
    } else {
        return nil;
    }
}

- (NSString *)dataToHex{
    
    const uint8_t *bytes = self.bytes;
    NSMutableString *hex = [[NSMutableString alloc] initWithCapacity:self.length*2];
    for (NSUInteger i = 0; i < self.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return  hex;
}



@end
