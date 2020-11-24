//
//  BIP39.h
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/23.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger,BIP39Language){
    BIP39LanguageDefault,
    BIP39LanguageEnglish,
    BIP39LanguageZhCN,
    BIP39LanguageZhTW
};
typedef NS_ENUM(NSInteger,BIP39WordCount){
    BIP39WordCount_12 = 12,
    BIP39WordCount_15 = 15,
    BIP39WordCount_18 = 18,
    BIP39WordCount_21 = 21,
    BIP39WordCount_24 = 24,
};

@interface HqBIP39 : NSObject

@property(nonatomic,assign) BIP39Language language;
@property(nonatomic,assign) BIP39WordCount wordCount;
- (NSString *)generateMnemonic;
- (NSArray *)generateMnemonicArray;
- (NSString *)generateMnemonicStrWithRandomData:(NSData *)data;
- (NSArray *)generateMnemonicWithRandomData:(NSData *)data;
- (NSData *)mnemonicToSeed:(NSString *)mnemonic withPassphrase:(NSString *)passphrase;

@end

NS_ASSUME_NONNULL_END
