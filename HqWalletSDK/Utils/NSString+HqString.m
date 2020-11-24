//
//  NSString+HqString.m
//  HqWalletSDK
//
//  Created by hehuiqi on 2020/11/12.
//

#import "NSString+HqString.h"
#import <openssl/bn.h>
#import "NSData+HqHash.h"
static const char base58chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void *secureAllocate(CFIndex allocSize, CFOptionFlags hint, void *info) {
    void *ptr = CFAllocatorAllocate(kCFAllocatorDefault, sizeof(CFIndex) + allocSize, hint);

    if (ptr) { // we need to keep track of the size of the allocation so it can be cleansed before deallocation
        *(CFIndex *) ptr = allocSize;
        return (CFIndex *) ptr + 1;
    }
    else return NULL;
}

static void secureDeallocate(void *ptr, void *info) {
    CFIndex size = *((CFIndex *) ptr - 1);

    if (size) {
        OPENSSL_cleanse(ptr, size);
        CFAllocatorDeallocate(kCFAllocatorDefault, (CFIndex *) ptr - 1);
    }
}

static void *secureReallocate(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info) {
    // There's no way to tell ahead of time if the original memory will be deallocted even if the new size is smaller
    // than the old size, so just cleanse and deallocate every time.
    void *newptr = secureAllocate(newsize, hint, info);
    CFIndex size = *((CFIndex *) ptr - 1);

    if (newptr) {
        if (size) {
            memcpy(newptr, ptr, size < newsize ? size : newsize);
            secureDeallocate(ptr, info);
        }

        return newptr;
    }
    else return NULL;
}
// Since iOS does not page memory to storage, all we need to do is cleanse allocated memory prior to deallocation.
CFAllocatorRef SecureAllocator() {
    static CFAllocatorRef alloc = NULL;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        CFAllocatorContext context;

        context.version = 0;
        CFAllocatorGetContext(kCFAllocatorDefault, &context);
        context.allocate = secureAllocate;
        context.reallocate = secureReallocate;
        context.deallocate = secureDeallocate;

        alloc = CFAllocatorCreate(kCFAllocatorDefault, &context);
    });

    return alloc;
}

@implementation NSString (HqString)



+ (NSString *)base58WithData:(NSData *)d {
    NSUInteger i = d.length * 138 / 100 + 2;
    char s[i];
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM base, x, r;

    BN_CTX_start(ctx);
    BN_init(&base);
    BN_init(&x);
    BN_init(&r);
    BN_set_word(&base, 58);
    BN_bin2bn(d.bytes, (int) d.length, &x);
    s[--i] = '\0';

    while (!BN_is_zero(&x)) {
        BN_div(&x, &r, &x, &base, ctx);
        s[--i] = base58chars[BN_get_word(&r)];
    }

    for (NSUInteger j = 0; j < d.length && *((const uint8_t *) d.bytes + j) == 0; j++) {
        s[--i] = base58chars[0];
    }

    BN_clear_free(&r);
    BN_clear_free(&x);
    BN_free(&base);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    NSString *ret = CFBridgingRelease(CFStringCreateWithCString(SecureAllocator(), &s[i], kCFStringEncodingUTF8));

    OPENSSL_cleanse(&s[0], d.length * 138 / 100 + 2);
    return ret;
}

+ (NSString *)base58checkWithData:(NSData *)d {
    NSMutableData *data = [[NSMutableData alloc] initWithData:d];

    [data appendBytes:d.SHA256_2.bytes length:4];

    return [self base58WithData:data];
}

- (NSData *)strToData{
    
    return  [self dataUsingEncoding:NSUTF8StringEncoding];
}
- (NSData *)hexToData {
    if (self.length % 2) return nil;
    NSMutableData *d = [[NSMutableData alloc] initWithCapacity:self.length / 2];
    uint8_t b = 0;

    for (NSUInteger i = 0; i < self.length; i++) {
        unichar c = [self characterAtIndex:i];

        switch (c) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                b += c - '0';
                break;
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                b += c + 10 - 'A';
                break;
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                b += c + 10 - 'a';
                break;
            default:
                return d;
        }

        if (i % 2) {
            [d appendBytes:&b length:1];
            b = 0;
        }
        else b *= 16;
    }

    return d;
}




@end
