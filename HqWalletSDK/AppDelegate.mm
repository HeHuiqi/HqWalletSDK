//
//  AppDelegate.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import "AppDelegate.h"
#import "HqMyUitl.hpp"
#import "CRIPEMD160.hpp"
#import "NSString+HqString.h"
#import "NSData+HqHash.h"
@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
//    [self test];
    
    return YES;
}

- (void)test{

    NSData *pubData = @"028f6daad48cf29cfddb86c6e65e600486c63e64ae66011073b2e2e8787d9b1697".hexToData;
    NSLog(@"pubData.RMD160==%@",pubData.RMD160.dataToHex);
    
    //    CRIPEMD160 *crp  = new CRIPEMD160();
    CRIPEMD160 crp;
    
    const unsigned char *data = (const unsigned char *)pubData.bytes;
    unsigned char hash[crp.OUTPUT_SIZE];
    crp.Write(data, 32).Finalize(hash);
    NSString *ddd = [[NSData alloc] initWithBytes:hash length:crp.OUTPUT_SIZE].dataToHex;
    NSLog(@"dddd==%@",ddd);
}
#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options  API_AVAILABLE(ios(13.0)){
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions  API_AVAILABLE(ios(13.0)){
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}


@end
