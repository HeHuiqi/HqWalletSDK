//
//  HqHDNode.h
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/19.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface HqHDNode : NSObject

@property(nonatomic,strong) NSData *privateKey;
@property(nonatomic,strong) NSData *chainCode;
@property(nonatomic,strong) NSData *publicKey;
@property(nonatomic,assign) int depth;
@property(nonatomic,assign) int childIndex;
@property(nonatomic,assign) NSData *fingerprint;

+ (HqHDNode *)initSeed:(NSData*)data network:(int)network;
- (HqHDNode *)derivedKeyPath:(NSString *)path;

@end

NS_ASSUME_NONNULL_END
