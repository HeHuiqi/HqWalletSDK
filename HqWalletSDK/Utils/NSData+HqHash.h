//
//  NSData+HqHash.h
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (HqHash)

- (NSData *)SHA1;

- (NSData *)SHA256;

- (NSData *)SHA256_2;

- (NSData *)RMD160;

- (NSData *)hash160;

//在推导ETH地址时需要使用非要锁公钥才能得到正确的地址
- (NSData *)keccak256;

- (NSData *)derivedPrivateKeyWithILData:(NSData *)iLData;
- (NSData *)derivedPublicKeyWithILData:(NSData *)iLData;

- (NSData *)reverse;

- (NSInteger)compare:(NSData *)data;

+ (NSData *)randomWithBits:(NSInteger)bits;
- (NSString *)dataToHex;
@end

NS_ASSUME_NONNULL_END
