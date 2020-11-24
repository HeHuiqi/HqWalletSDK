//
//  HqHDNode.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/19.
//

#import "HqHDNode.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import <secp256k1.h>
#import <secp256k1_recovery.h>
#import "NSData+HqHash.h"
#import "NSString+HqString.h"

#define HARDENED_OFFSET  0x80000000
#define LEN  78
#define xprivkey 0x0488ADE4
#define xpubkey  0x0488B21E
    
@interface HqHDNode()



@end

@implementation HqHDNode

NSData *hmacSha512WithData(NSData *hashData, NSData *hmacKeyData){
    unsigned char *digest;
    digest = malloc(CC_SHA512_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA512, hmacKeyData.bytes, hmacKeyData.length, hashData.bytes, hashData.length, digest);
  
    NSData *result = [[NSData alloc] initWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
    return result;
}
+ (HqHDNode *)initSeed:(NSData*)data network:(int)network{
    NSString *hmackey = @"Bitcoin seed";
    NSData *hmackeyData = [hmackey dataUsingEncoding:(NSUTF8StringEncoding)];
    NSData *hmac = hmacSha512WithData(data, hmackeyData);

//    NSLog(@"seed-hmac==%@",hmac.dataToHex);
    
    HqHDNode *rootNode = [[HqHDNode alloc] init];
    
    NSData *privateKey = [hmac subdataWithRange:NSMakeRange(0, 32)];
    NSData *chainCode = [hmac subdataWithRange:NSMakeRange(32, 32)];
    rootNode.privateKey = privateKey;
    rootNode.chainCode = chainCode;
    rootNode.childIndex = 0;
    rootNode.depth = 0;
    return rootNode;
}
+ (HqHDNode *)initNode:(NSData*)privateKey publicKey:(NSData *)publicKey chainCode:(NSData *)chainCode depth:(UInt8)depth fingerprint:(NSData *)fingerprint childIndex:(UInt32)childIndex {
    HqHDNode *node = [[HqHDNode alloc] init];
    node.privateKey = privateKey;
    node.publicKey = publicKey;
    node.chainCode = chainCode;
    node.depth = depth;
    node.childIndex = childIndex;
    node.fingerprint = fingerprint;
    return node;
}

- (HqHDNode *)derivedKeyPath:(NSString *)path {

    HqHDNode *currentNode = self;
    if ([path isEqualToString:@"m"] ||
        [path isEqualToString:@"/"] ||
        [path isEqualToString:@""]) {
        return currentNode;
    }
    
    if ([path containsString:@"m/"]) {
        path = [path substringFromIndex:2];
    }
    NSArray *components = [path componentsSeparatedByString:@"/"];
    for (NSString *chunk in components) {
        BOOL hardened = NO;
        NSString *indexText = chunk;
        
        if ([chunk containsString:@"'"]) {
            hardened = YES;
            indexText = [indexText substringToIndex:indexText.length-1];
        }
        UInt32 index = indexText.intValue;
//        NSLog(@"index==%@",@(index));

        currentNode = [currentNode derived:index hardened:hardened];
    }
    
    return currentNode;
}


- (NSData *)priToPub:(NSData *)pri compressed:(BOOL)compressed{
    const unsigned char *seckey = (const unsigned char *)pri.bytes;
    
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
//    NSLog(@"pubHex==%@",pubData.dataToHex);
    secp256k1_context_destroy(ctx);
    
//    secp256k1_ec_privkey_tweak_add
    
    return  pubData;
}

-(HqHDNode *)derived:(UInt32)childIndex hardened:(BOOL)hardened {
    
//    printf("1---self.chainCode==%s\n",self.chainCode.dataToHex.UTF8String);

    if ((0x80000000 & childIndex) != 0) {
        NSLog(@"invalid child index");
        return nil;
    }
    /**
     d8377867f845f9fe20936c1abc16ad271c1fa3a57a1d166675f291b5a61d49af
     78c2dbecc9b62fbe9d5b5fdffa81071c9963c7585615045a792e59ed9b370129

     */
    NSMutableData *data = [[NSMutableData alloc] init];
    if (hardened) {
//        char zero1[1] = {0x0};
//        [data appendBytes:zero length:1];
        int zero = 0;
        [data appendBytes:&zero length:1];

        [data appendData:self.privateKey];
    } else {
        [data appendData:self.publicKey];
    }
//    NSLog(@"1---hardened==%@",hardened ? @"true":@"false");

//    NSLog(@"1---childIndex==%@",@(childIndex));

//    printf("1---childIndex==%d\n",childIndex);


    childIndex = hardened ? 0x80000000 | childIndex : childIndex;
    childIndex = CFSwapInt32HostToBig(childIndex);
//    NSLog(@"2---childIndex==%@",@(childIndex));
    NSData *indexData = [[NSData alloc] initWithBytes:&childIndex length:4];
    [data appendData:indexData];
    NSData *digest = hmacSha512WithData(data, self.chainCode);
//    NSLog(@"1---digest==%@",digest.dataToHex);


    NSData *derivedKey_IL = [digest subdataWithRange:NSMakeRange(0, 32)];
    NSData *derivedChainCode_IR = [digest subdataWithRange:NSMakeRange(32, 32)];
    NSData *result;
    
    //父私钥->子私钥
    if (self.privateKey) {
        
        /*
        printf("1-----privateKey==%s\n",self.privateKey.dataToHex.UTF8String);
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        unsigned char *privateKeyBytes = ( unsigned char *)self.privateKey.bytes;

        const unsigned char * derivedPrivateKeyBytes = (const unsigned char *) derivedKey_IL.bytes;
        if (secp256k1_ec_privkey_tweak_add(ctx, privateKeyBytes, derivedPrivateKeyBytes) == 0) {
            secp256k1_context_destroy(ctx);
            return nil;
        }
        printf("pri-----derivedPrivateKey==%s\n",derivedKey_IL.dataToHex.UTF8String);

        //获得子私钥
        result = [[NSData alloc] initWithBytes:privateKeyBytes length:32];
        printf("2-----privateKey==%s\n",result.dataToHex.UTF8String);
         */
        
        result = [self.privateKey derivedPrivateKeyWithILData:derivedKey_IL];
        //子私钥对应的压缩公钥
        if (result == nil) {
            return nil;
        }
        self.publicKey = [self priToPub:result compressed:YES];
    }
    else {
        //父公钥->子公钥
        /*
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        
        unsigned char *publicKeyBytes = (unsigned char *)self.publicKey.bytes;
        secp256k1_pubkey secpPubkey;
        if (secp256k1_ec_pubkey_parse(ctx, &secpPubkey, publicKeyBytes, self.publicKey.length) == 0) {
            secp256k1_context_destroy(ctx);
            return nil;
        }
        if (secp256k1_ec_pubkey_tweak_add(ctx, &secpPubkey, derivedKey_IL.bytes) == 0) {
            secp256k1_context_destroy(ctx);
            return nil;
        }
        
        size_t compressedPublicKeyBytesLen = 33;
        unsigned char compressedPublicKeyBytes[compressedPublicKeyBytesLen];
        if (secp256k1_ec_pubkey_serialize(ctx, compressedPublicKeyBytes, &compressedPublicKeyBytesLen, &secpPubkey,SECP256K1_EC_COMPRESSED)) {
            return nil;
        }
      
        self.publicKey =  [[NSData alloc] initWithBytes:compressedPublicKeyBytes length:33];
        */
        
        self.publicKey = [self.publicKey derivedPublicKeyWithILData:derivedKey_IL];
    }
 
    NSData *fingerPrint  = self.privateKey.hash160;
    if (fingerPrint.length>4) {
        fingerPrint = [fingerPrint subdataWithRange:NSMakeRange(0, 4)];
    }
    HqHDNode *node = [HqHDNode initNode:result publicKey:self.publicKey chainCode:derivedChainCode_IR depth:self.depth + 1 fingerprint:fingerPrint childIndex:childIndex];
    return node;
}





@end
