//
//  HqWallet.h
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HqWallet : NSObject

@property(nonatomic,copy) NSString *mnemonic;
@property(nonatomic,copy) NSString *saltPs;
@property(nonatomic,strong) NSData *privateKey;
@property(nonatomic,strong) NSData *publicKey;
@property(nonatomic,copy) NSString *wifPrivatekey;//仅用用于BTC私钥格式
@property(nonatomic,copy) NSString *address;

- (void)testMethod;

#pragma mark - Wallet
- (NSData *)priToPub:(NSString *)pri compressed:(BOOL)compressed;
- (NSData *)opensslPriToPub:(NSString *)pri compressed:(BOOL)compressed;
- (NSString *)btcWIFPrivatekey:(NSString *)prikey compressed:(BOOL)compressed;
- (NSString *)btcAddressWithPubKey:(NSString *)pubKey;
- (NSString *)eosWIFPrivatekey:(NSString *)prikey;
- (NSString *)eosAddressWithPubKey:(NSString *)pubKey;
- (NSData *)pubkey_combine:(NSData *)pubkeyData;
- (NSString *)ethAddressWithPubKey:(NSString *)pubKey;
#pragma mark - Sign
- (NSData *)recoverSignHashMessage:(NSData *)hashMessage privateKey:(NSData *)privateKey;
- (NSData *)signHashMessage:(NSData *)hashMessage privateKey:(NSData *)privateKey;
- (BOOL)verifySign:(NSData *)signData hashMessage:(NSData *)hashMessage pubKey:(NSData *)pubKey;

- (void)test_pressed_pubkey_combinePub;
- (NSString *)opensslSignData:(NSData *)data privateKey:(NSString *)privateKey;

void tes_sigh(void);
@end

NS_ASSUME_NONNULL_END
