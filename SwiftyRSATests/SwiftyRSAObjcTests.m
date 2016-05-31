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

- (void)testSignVerify {
    
    NSMutableData* data = [NSMutableData dataWithCapacity:2048 * sizeof(UInt32)];
    for (unsigned int i = 0 ; i < 2048 ; ++i ){
        u_int32_t randomBits = arc4random();
        [data appendBytes:(void*)&randomBits length:sizeof(UInt32)];
    }
    NSString* testString = @"Lorum Ipsum Ipso Facto Ad Astra Ixnay Onay Ayway";
    
    NSString* pubString = [TestUtils pemKeyStringWithName:@"swiftyrsa-public"];
    NSString* privString = [TestUtils pemKeyStringWithName:@"swiftyrsa-private"];
    NSData* pubData = [TestUtils derKeyDataWithName:@"swiftyrsa-public"];
    
    NSError* error;
    
    DigestType hashingMethods[] = {DigestTypeSHA1,DigestTypeSHA224,DigestTypeSHA256,DigestTypeSHA384,DigestTypeSHA512};
    
    for (int i=0; i<5; i++) {
        NSData* digestSignature = [SwiftyRSA signData:data privateKeyPEM:privString digestMethod:hashingMethods[i] error:&error];
        XCTAssertNil(error);
        
        VerificationResult* result = [SwiftyRSA verifySignatureData:data signature:digestSignature publicKeyPEM:pubString digestMethod:hashingMethods[i] error:&error];
        XCTAssertNil(error);
        XCTAssert(result.boolValue);
        
        NSString *digestString = [SwiftyRSA signString:testString privateKeyPEM:privString digestMethod:hashingMethods[i] error:&error];
        XCTAssertNil(error);
        
        result = [SwiftyRSA verifySignatureString:testString signature:digestString publicKeyPEM:pubString digestMethod:hashingMethods[i] error:&error];
        XCTAssertNil(error);
        XCTAssert(result.boolValue);
        
        result = [SwiftyRSA verifySignatureString:testString signature:digestString publicKeyDER:pubData digestMethod:hashingMethods[i] error:&error];
        XCTAssertNil(error);
        XCTAssert(result.boolValue);
    }
    
    
    SwiftyRSA* rsa=[[SwiftyRSA alloc]init];
    
    SecKeyRef pubKey = [rsa publicKeyFromPEMString:pubString error:&error];
    
    XCTAssertNil(error);
    
    SecKeyRef privKey = [rsa privateKeyFromPEMString:privString error:&error];
    
    XCTAssertNil(error);
    
    NSData* digest = [data SwiftyRSASHA1];
    
    NSData* digestSignature = [rsa signSHA1Digest:digest privateKey:privKey error:&error];
    
    XCTAssertNil(error);
    
    VerificationResult* result = [rsa verifySHA1SignatureData:digest signature:digestSignature publicKey:pubKey error:&error];
    
    XCTAssertNil(error);
    XCTAssert(result.boolValue);

    digest = [data SwiftyRSASHA224];
    digestSignature = [rsa signDigest:digest privateKey:privKey digestMethod:DigestTypeSHA224 error:&error];
    
    XCTAssertNil(error);
    
    result = [rsa verifySignatureData:digest signature:digestSignature publicKey:pubKey digestMethod:DigestTypeSHA224 error:&error];
    
    XCTAssertNil(error);
    XCTAssert(result.boolValue);
    
    digest = [data SwiftyRSASHA256];
    digestSignature = [rsa signDigest:digest privateKey:privKey digestMethod:DigestTypeSHA256 error:&error];
    
    XCTAssertNil(error);
    
    result = [rsa verifySignatureData:digest signature:digestSignature publicKey:pubKey digestMethod:DigestTypeSHA256 error:&error];
    
    XCTAssertNil(error);
    XCTAssert(result.boolValue);
    
    digest = [data SwiftyRSASHA384];

    digestSignature = [rsa signDigest:digest privateKey:privKey digestMethod:DigestTypeSHA384 error:&error];
    
    XCTAssertNil(error);
    
    result = [rsa verifySignatureData:digest signature:digestSignature publicKey:pubKey digestMethod:DigestTypeSHA384 error:&error];
    
    XCTAssertNil(error);
    XCTAssert(result.boolValue);
    
    digest = [data SwiftyRSASHA512];

    digestSignature = [rsa signDigest:digest privateKey:privKey digestMethod:DigestTypeSHA512 error:&error];
    
    XCTAssertNil(error);
    
    result = [rsa verifySignatureData:digest signature:digestSignature publicKey:pubKey digestMethod:DigestTypeSHA512 error:&error];
    
    XCTAssertNil(error);
    XCTAssert(result.boolValue);
    
}

@end
