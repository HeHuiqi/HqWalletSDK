//
//  NSString+HqString.h
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSString (HqString)

+ (NSString *)base58WithData:(NSData *)d;
+ (NSString *)base58checkWithData:(NSData *)d;
- (NSData *)strToData;
- (NSData *)hexToData;

@end

NS_ASSUME_NONNULL_END
