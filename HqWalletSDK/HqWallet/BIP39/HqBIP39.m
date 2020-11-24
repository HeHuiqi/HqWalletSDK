//
//  BIP39.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/23.
//

#import "HqBIP39.h"
#import "NSData+HqHash.h"
#import <CommonCrypto/CommonKeyDerivation.h>
@implementation HqBIP39

- (BIP39Language)language{
    if (_language == BIP39LanguageDefault) {
        return BIP39LanguageEnglish;
    }
    return _language;
}
- (BIP39WordCount)wordCount{
    if (_wordCount  == 0) {
        return BIP39WordCount_12;
    }
    
    return _wordCount;
}

- (NSArray *)allWords{
    NSString *language = @"BIP39EnglishWords";
    switch (self.language) {
        case BIP39LanguageZhCN:
            language = @"BIP39ZhCNWords";
            break;
        case BIP39LanguageZhTW:
            language = @"BIP39ZhTWWords";
            break;
            
        default:
            break;
    }
    NSString *path = [[NSBundle mainBundle] pathForResource:language ofType:@"plist"];
    return [[NSArray alloc] initWithContentsOfFile:path];
}
- (NSInteger)randomLen{
    
    NSInteger len = self.wordCount * 11 - self.wordCount/3;
    return len;
}
- (NSString *)generateMnemonic{
    NSInteger len = [self randomLen];
    NSData *randomData = [NSData randomWithBits:len];
    return [self generateMnemonicStrWithRandomData:randomData];
}

- (NSArray *)generateMnemonicArray{
    NSInteger len = [self randomLen];
    NSData *randomData = [NSData randomWithBits:len];
    return [self generateMnemonicWithRandomData:randomData];
}
- (NSString *)generateMnemonicStrWithRandomData:(NSData *)data{
    
    NSArray *words = [self generateMnemonicWithRandomData:data];
    if (words.count > 0) {
        return [words componentsJoinedByString:@" "];
    }
    return nil;
   
}
- (NSArray *)generateMnemonicWithRandomData:(NSData *)data {
    if ((data.length % 4) != 0 || data.length == 0) return nil; // data length must be a multiple of 32 bits
    NSArray *words = [self allWords];
    uint32_t n = (uint32_t) words.count, x;
    NSMutableArray *a = [[NSMutableArray alloc] init];
    NSMutableData *d = [[NSMutableData alloc] initWithData:data];
    [d appendData:data.SHA256]; // append SHA256 checksum

    for (int i = 0; i < data.length * 3 / 4; i++) {
        x = CFSwapInt32BigToHost(*(const uint32_t *) ((const uint8_t *) d.bytes + i * 11 / 8));
        [a addObject:words[(x >> (sizeof(x) * 8 - (11 + ((i * 11) % 8)))) % n]];
    }
    return a;
}

- (NSData *)mnemonicToSeed:(NSString *)mnemonic withPassphrase:(NSString *)passphrase {
    NSMutableData *key = [[NSMutableData alloc] initWithLength:CC_SHA512_DIGEST_LENGTH];
    NSData *password, *salt;
    CFAllocatorRef  allocatorRef = CFAllocatorGetDefault();
    CFMutableStringRef pw = CFStringCreateMutableCopy(allocatorRef, mnemonic.length, (__bridge CFStringRef) mnemonic);
    CFMutableStringRef s = CFStringCreateMutableCopy(allocatorRef, 8 + passphrase.length, CFSTR("mnemonic"));
    if (passphrase) CFStringAppend(s, (__bridge CFStringRef) passphrase);
    CFStringNormalize(pw, kCFStringNormalizationFormKD);
    CFStringNormalize(s, kCFStringNormalizationFormKD);
    password = CFBridgingRelease(CFStringCreateExternalRepresentation(allocatorRef, pw, kCFStringEncodingUTF8, 0));
    salt = CFBridgingRelease(CFStringCreateExternalRepresentation(allocatorRef, s, kCFStringEncodingUTF8, 0));
    CFRelease(pw);
    CFRelease(s);

    CCKeyDerivationPBKDF(kCCPBKDF2, password.bytes, password.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA512, 2048,
            key.mutableBytes, key.length);
    return key;
}

@end
