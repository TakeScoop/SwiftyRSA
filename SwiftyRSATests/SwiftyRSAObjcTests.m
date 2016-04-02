//
//  SwiftyRSAObjcTests.m
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 1/28/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

#import <XCTest/XCTest.h>
@import SwiftyRSA;

@interface SwiftyRSAObjcTests : XCTestCase

@end

@implementation SwiftyRSAObjcTests

- (void)testClassPEM {
    NSString* str = @"ClearText";
    
    NSBundle* bundle = [NSBundle bundleForClass:self.class];
    
    NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public" ofType:@"pem"];
    NSString* pubString = [NSString stringWithContentsOfFile:pubPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString* privPath = [bundle pathForResource:@"swiftyrsa-private" ofType:@"pem"];
    NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString* encrypted = [SwiftyRSA encryptString:str publicKeyPEM:pubString padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [SwiftyRSA decryptString:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testClassDER {
    NSString* str = @"ClearText";
    
    NSBundle* bundle = [NSBundle bundleForClass:self.class];
    
    NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public" ofType:@"der"];
    NSData* pubData = [NSData dataWithContentsOfFile:pubPath];
    
    NSString* privPath = [bundle pathForResource:@"swiftyrsa-private" ofType:@"pem"];
    NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString* encrypted = [SwiftyRSA encryptString:str publicKeyDER:pubData padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [SwiftyRSA decryptString:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testPEM {
    NSString* str = @"ClearText";
    
    NSBundle* bundle = [NSBundle bundleForClass:self.class];
    
    SwiftyRSA* rsa = [SwiftyRSA new];
    
    
    NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public" ofType:@"pem"];
    NSString* pubString = [NSString stringWithContentsOfFile:pubPath encoding:NSUTF8StringEncoding error:nil];
	SecKeyRef pubKey = [rsa publicKeyFromPEMString:pubString error:nil];
    
    NSString* privPath = [bundle pathForResource:@"swiftyrsa-private" ofType:@"pem"];
    NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];
    SecKeyRef privKey = [rsa privateKeyFromPEMString:privString error:nil];
    
    NSString* encrypted = [rsa encryptString:str publicKey:pubKey padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [rsa decryptString:encrypted privateKey:privKey padding:kSecPaddingPKCS1 error: nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testDER {
    NSString* str = @"ClearText";
    
    NSBundle* bundle = [NSBundle bundleForClass:self.class];
    
    SwiftyRSA* rsa = [SwiftyRSA new];
    
    NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public" ofType:@"der"];
    NSData* pubData = [NSData dataWithContentsOfFile:pubPath];
    SecKeyRef pubKey = [rsa publicKeyFromDERData:pubData error:nil];
    
    NSString* privPath = [bundle pathForResource:@"swiftyrsa-private" ofType:@"pem"];
    NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];
    SecKeyRef privKey = [rsa privateKeyFromPEMString:privString error:nil];
    
    NSString* encrypted = [rsa encryptString:str publicKey:pubKey padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [rsa decryptString:encrypted privateKey:privKey padding:kSecPaddingPKCS1 error: nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testPEMHeaderless {
    NSString* str = @"ClearText";
    
    NSBundle* bundle = [NSBundle bundleForClass:self.class];
    
    SwiftyRSA* rsa = [SwiftyRSA new];
    
    
    NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public-headerless" ofType:@"pem"];
    NSString* pubString = [NSString stringWithContentsOfFile:pubPath encoding:NSUTF8StringEncoding error:nil];
    SecKeyRef pubKey = [rsa publicKeyFromPEMString:pubString error:nil];
    
    NSString* privPath = [bundle pathForResource:@"swiftyrsa-private-headerless" ofType:@"pem"];
    NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];
    SecKeyRef privKey = [rsa privateKeyFromPEMString:privString error:nil];
    
    NSString* encrypted = [rsa encryptString:str publicKey:pubKey padding:kSecPaddingPKCS1 error:nil];
    NSString* decrypted = [rsa decryptString:encrypted privateKey:privKey padding:kSecPaddingPKCS1 error: nil];
    
    XCTAssertTrue([str isEqualToString:decrypted]);
}

- (void)testDataEncryptDecrypt {
    
    
    NSMutableData* data = [NSMutableData dataWithCapacity:2048 * sizeof(UInt32)];
    for (unsigned int i = 0 ; i < 2048 ; ++i ){
        u_int32_t randomBits = arc4random();
        [data appendBytes:(void*)&randomBits length:sizeof(UInt32)];
    }
    
    NSBundle* bundle = [NSBundle bundleForClass:self.class];
    
    NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public" ofType:@"pem"];
    NSString* pubString = [NSString stringWithContentsOfFile:pubPath encoding:NSUTF8StringEncoding error:nil];
    
    NSString* privPath = [bundle pathForResource:@"swiftyrsa-private" ofType:@"pem"];
    NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];
    
    NSData* encrypted = [SwiftyRSA encryptData:data publicKeyPEM:pubString padding:kSecPaddingPKCS1 error:nil];
    NSData* decrypted = [SwiftyRSA decryptData:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
    
    XCTAssertTrue([data isEqualToData:decrypted]);
}

@end
