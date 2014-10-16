//
//  XCipher.m
//  wepay
//
//  Created by hhfa on 14-10-13.
//  Copyright (c) 2014年 hhfa. All rights reserved.
//

#import "XCipher.h"

@implementation XCipher

@synthesize algorithm;

@synthesize options;

@synthesize key;

@synthesize keySize;

@synthesize blockSize;

-(id) initWithAlgorithm:(CCAlgorithm)alg
{
    self = [super init];
    if (self) {
        self.algorithm = alg;

        //根据加解算法初始化默认参数
        switch (alg) {
            case kCCAlgorithmAES128:
                self.options   = kCCOptionPKCS7Padding | kCCOptionECBMode;
                self.keySize   = kCCKeySizeAES128;
                self.blockSize = kCCBlockSizeAES128;
                break;
            case kCCAlgorithmDES:
                self.options   = kCCOptionPKCS7Padding;
                self.keySize   = kCCKeySizeDES;
                self.blockSize = kCCBlockSizeDES;
                break;
            case kCCAlgorithm3DES:
                self.options   = kCCOptionECBMode;
                self.keySize   = kCCKeySize3DES;
                self.blockSize = kCCBlockSize3DES;
                break;
            //TODO 根据实际需求添加其他加密算法的默认初始化
            default:
                break;
        }
    }
    return self;
}

-(BOOL) encryptFile:(NSString*)fileIn to:(NSString*)fileOut
{
    NSData* src = [NSData dataWithContentsOfFile:fileIn];
    if (nil == src)
    {
        return NO;
    }
    NSData* data = [self cryptData:src withOperation:kCCEncrypt];
    return [data writeToFile:fileOut atomically:YES];
}

-(BOOL) decryptFile:(NSString*)fileIn to:(NSString*)fileOut
{
    NSData* src = [NSData dataWithContentsOfFile:fileIn];
    if (nil == src)
    {
        return NO;
    }
    NSData* data = [self cryptData:src withOperation:kCCDecrypt];
    return [data writeToFile:fileOut atomically:YES];
}

-(NSData*) decryptFile:(NSString*)filePath
{
    NSData* src = [NSData dataWithContentsOfFile:filePath];
    if (nil == src)
    {
        return nil;
    }
    return [self cryptData:src withOperation:kCCDecrypt];
}

-(BOOL) encryptData:(NSData*)sourceData toFile:(NSString*)fileOut
{
    NSData* data = [self cryptData:sourceData withOperation:kCCEncrypt];
    return [data writeToFile:fileOut atomically:YES];
}

-(NSData*) encryptData:(NSData*)sourceData
{
    return [self cryptData:sourceData withOperation:kCCEncrypt];
}

-(NSData*) decryptData:(NSData*)sourceData
{
    return [self cryptData:sourceData withOperation:kCCDecrypt];
}

-(NSData*) cryptData:(NSData*)sourceData withOperation:(CCOperation)op
{
    NSData* result       = nil;
    const void *keyBytes = [self.key bytes];//密钥.
    const void *iv       = NULL;//initialization vector (optional)
    
    
    if (self.iv) {
            NSData * date = [self.iv dataUsingEncoding:NSUTF8StringEncoding];
        iv = date.bytes;
    }
    Byte byIv[] = { 68, 5, 41, 51, 33, 124, 87, 85 };

    const void *dataIn = [sourceData bytes];//加密或解密，长度dataInLength字节的数据。
    size_t dataInLength = [sourceData length];
    size_t dataOutAvilable = [sourceData length] + self.blockSize;//输出块的大小小于等于输入大小加一个块的大小
    void *dataOut = malloc(dataOutAvilable);//存放加解密后的数据
    size_t dataOutMoved = 0;

    CCCryptorStatus cryptStatus = CCCrypt(op, self.algorithm, self.options, keyBytes, self.keySize, byIv,
                                          dataIn, dataInLength, dataOut, dataOutAvilable, &dataOutMoved);

    if(cryptStatus == kCCSuccess)
    {
        result = [NSData dataWithBytes:(const void*)dataOut length:(NSUInteger)dataOutMoved];
    }
    free(dataOut);
    return result;
}

@end
