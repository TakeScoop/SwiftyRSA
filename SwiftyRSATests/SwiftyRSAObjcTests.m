//
//  SwiftyRSAObjcTests.m
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 1/28/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SwiftyRSATests-Swift.h"
@import SwiftyRSA;

@interface SwiftyRSAObjcTests : XCTestCase

@end

@implementation SwiftyRSAObjcTests

- (void)testClassPEM {
    NSString* str = @"ClearText";
    
    NSString* pubString = [TestUtils pemKeyStringWithName:@"swiftyrsa-public"];
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private"];
    
    NSString* encrypted = [SwiftyRSA encryptString:str publicKeyPEM:pubString padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [SwiftyRSA decryptString:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testClassDER {
    NSString* str = @"ClearText";
    
    NSData* pubData = [TestUtils derKeyDataWithName:@"swiftyrsa-public"];
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private"];
    
    NSString* encrypted = [SwiftyRSA encryptString:str publicKeyDER:pubData padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [SwiftyRSA decryptString:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testPEM {
    NSString* str = @"ClearText";
    
    SwiftyRSA* rsa = [SwiftyRSA new];
    
    NSString* pubString = [TestUtils pemKeyStringWithName:@"swiftyrsa-public"];
	SecKeyRef pubKey = [rsa publicKeyFromPEMString:pubString error:nil];
    
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private"];
    SecKeyRef privKey = [rsa privateKeyFromPEMString:privString error:nil];
    
    NSString* encrypted = [rsa encryptString:str publicKey:pubKey padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [rsa decryptString:encrypted privateKey:privKey padding:kSecPaddingPKCS1 error: nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testDER {
    NSString* str = @"ClearText";
    
    SwiftyRSA* rsa = [SwiftyRSA new];
    
    NSData* pubData = [TestUtils derKeyDataWithName:@"swiftyrsa-public"];
    SecKeyRef pubKey = [rsa publicKeyFromDERData:pubData error:nil];
    
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private"];
    SecKeyRef privKey = [rsa privateKeyFromPEMString:privString error:nil];
    
    NSString* encrypted = [rsa encryptString:str publicKey:pubKey padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [rsa decryptString:encrypted privateKey:privKey padding:kSecPaddingPKCS1 error: nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testPEMHeaderless {
    NSString* str = @"ClearText";
    
    NSString* pubString = [TestUtils pemKeyStringWithName:@"swiftyrsa-public-headerless"];
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private-headerless"];
    
    NSString* encrypted = [SwiftyRSA encryptString:str publicKeyPEM:pubString padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [SwiftyRSA decryptString:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testDataEncryptDecrypt {
    
    
    NSMutableData* data = [NSMutableData dataWithCapacity:2048 * sizeof(UInt32)];
    for (unsigned int i = 0 ; i < 2048 ; ++i ){
        u_int32_t randomBits = arc4random();
        [data appendBytes:(void*)&randomBits length:sizeof(UInt32)];
    }
    
    NSString* pubString = [TestUtils pemKeyStringWithName:@"swiftyrsa-public"];
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private"];
    
    NSData* encrypted = [SwiftyRSA encryptData:data publicKeyPEM:pubString padding:kSecPaddingPKCS1 error:nil];
    NSData* decrypted = [SwiftyRSA decryptData:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([data isEqualToData:decrypted]);
}

@end
