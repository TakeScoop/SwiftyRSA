//
//  NSData_SHA1.h
//  SwiftyRSA
//
//  Created by Paul Wilkinson on 19/04/2016.
//  Copyright © 2016 Scoop. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation NSData (NSData_SHA)

- (nonnull NSData*) SHA1 {
    unsigned int outputLength = CC_SHA1_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA1(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) SHA224 {
    unsigned int outputLength = CC_SHA224_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA224(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) SHA256 {
    unsigned int outputLength = CC_SHA256_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA256(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) SHA384 {
    unsigned int outputLength = CC_SHA384_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA384(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) SHA512 {
    unsigned int outputLength = CC_SHA512_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA512(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

@end