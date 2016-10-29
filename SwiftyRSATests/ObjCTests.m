//
//  ObjCTests.m
//  SwiftyRSA
//
//  Created by Lois Di Qual on 9/29/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SwiftyRSATests-Swift.h"

@import SwiftyRSA;

@interface SwiftyRSAObjcTests : XCTestCase

@end

@implementation SwiftyRSAObjcTests

/**
 * These acts essentially as smoke tests to ensure that all the following methods are available in an ObjC context.
 * The actual unit tests are done in Swift in the same target.
 */
- (void)test_smoke {
    NSData* data = [TestUtils randomDataWithCount:128];
    
    [[PublicKey alloc] initWithData:data error:nil];
    [[PublicKey alloc] initWithPemEncoded:@"test" error:nil];
    [[PublicKey alloc] initWithBase64Encoded:@"test" error:nil];
    [[PublicKey alloc] initWithPemNamed:@"test" in: [NSBundle bundleForClass:[TestUtils class]] error:nil];
    [[PublicKey alloc] initWithDerNamed:@"test" in: [NSBundle bundleForClass:[TestUtils class]] error:nil];
    [PublicKey publicKeysWithPemEncoded:@"test"];
    
    [[PrivateKey alloc] initWithData:data error:nil];
    [[PrivateKey alloc] initWithPemEncoded:@"test" error:nil];
    [[PrivateKey alloc] initWithPemNamed:@"test" in: [NSBundle bundleForClass:[TestUtils class]] error:nil];
    [[PrivateKey alloc] initWithDerNamed:@"test" in: [NSBundle bundleForClass:[TestUtils class]] error:nil];
    [[PrivateKey alloc] initWithBase64Encoded:@"test" error:nil];
    
    [[Signature alloc] initWithBase64Encoded:@"test" error:nil];
    [[Signature alloc] initWithData:data];
    
    [[ClearMessage alloc] initWithBase64Encoded:@"test" error:nil];
    [[ClearMessage alloc] initWithData:data];
    [[ClearMessage alloc] initWithString:@"test" using:NSUTF8StringEncoding error:nil];
    
    {
        PublicKey* publicKey = [TestUtils publicKeyWithName:@"swiftyrsa-public" error:nil];
        PrivateKey* privateKey = [TestUtils privateKeyWithName:@"swiftyrsa-private" error:nil];
        Signature* signature = [[Signature alloc] initWithData:data];
        ClearMessage* clearMessage = [[ClearMessage alloc] initWithData:data];
        [clearMessage data];
        [clearMessage base64String];
        [clearMessage encryptedWith:publicKey padding:kSecPaddingNone error:nil];
        [clearMessage signedWith:privateKey digestType:DigestTypeSha1 error:nil];
        [clearMessage verifyWith:publicKey signature:signature digestType:DigestTypeSha1 error:nil];
    }
    
    {
        PrivateKey* privateKey = [TestUtils privateKeyWithName:@"swiftyrsa-private" error:nil];
        EncryptedMessage* encryptedMessage = [[EncryptedMessage alloc] initWithData:data];
        [encryptedMessage data];
        [encryptedMessage base64String];
        [encryptedMessage decryptedWith:privateKey padding:kSecPaddingNone error:nil];
    }
}

@end
