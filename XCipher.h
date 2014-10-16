//
//  XCipher.h
//  wepay
//
//  Created by hhfa on 14-10-13.
//  Copyright (c) 2014年 hhfa. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

/**
	提供加解密常用工具方法
 */
@interface XCipher : NSObject

/**
    加解密算法
 */
@property CCAlgorithm algorithm;

/**
    加解密参数选项，包括填充算法等
 */
@property CCOptions   options;

/**
    密钥
 */
@property NSData*     key;

@property (copy) NSString*     iv;

/**
    密钥长度
 */
@property size_t      keySize;

/**
    块长度
 */
@property size_t      blockSize;

/**
   根据加密算法初始化默认参数,
   对于kCCAlgorithmAES128：
   options = PKCS7Padding | kCCOptionECBMode,
   keySize = 16
   blockSize = kCCBlockSizeAES128

   对于kCCAlgorithmDES:
   options = PKCS7Padding | kCCOptionECBMode,
   keySize = 8
   blockSize = kCCBlockSizeDES

   对于kCCAlgorithm3DES:
   options = PKCS7Padding,
   keySize = 24
   blockSize = kCCBlockSize3DES

   @param  alg 指定加解密算法
 */
-(id) initWithAlgorithm:(CCAlgorithm)alg;

/**
    加密文件
    @param fileIn 待处理的的文件路径
    @param fileOut 保存加密结果的文件路径
    @returns 成功返回YES，失败返回NO
 */
-(BOOL) encryptFile:(NSString*)fileIn to:(NSString*)fileOut;

/**
    解密文件
    @param fileIn 待处理的的文件路径
    @param fileOut 保存解密结果的文件路径
    @returns 成功返回YES，失败返回NO
 */
-(BOOL) decryptFile:(NSString*)fileIn to:(NSString*)fileOut;

/**
    解密文件并返回NSData
    @param filePath 待处理的的文件路径
    @returns 成功返回解密后的数据，失败返回nil
 */
-(NSData*) decryptFile:(NSString*)filePath;

/**
    加密数据并保存到文件
    @param sourceData 待处理的数据
    @param fileOut    保存加密结果的文件路径
    @returns 成功返回加密后的数据，失败返回nil
 */
-(BOOL) encryptData:(NSData*)sourceData toFile:(NSString*)fileOut;

/**
    加密数据
    @param sourceData 待处理的数据
    @returns 成功返回加密后的数据，失败返回nil
 */
-(NSData*) encryptData:(NSData*)sourceData;

/**
    解密数据
    @param sourceData 待处理的数据
    @returns 成功返回解密后的数据，失败返回nil
 */
-(NSData*) decryptData:(NSData*)sourceData;

/**
    加密或解密数据
    @param sourceData 待处理的数据
    @returns 成功返回加密或解密的数据，失败返回nil
 */
-(NSData*) cryptData:(NSData*)sourceData withOperation:(CCOperation)op;
@end
