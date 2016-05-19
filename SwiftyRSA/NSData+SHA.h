//
//  NSData_SHA1.h
//  SwiftyRSA
//
//  Created by Paul Wilkinson on 19/04/2016.
//  Copyright © 2016 Scoop. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NSData_SHA)

- (nonnull NSData*) SHA1;
- (nonnull NSData*) SHA224;
- (nonnull NSData*) SHA256;
- (nonnull NSData*) SHA384;
- (nonnull NSData*) SHA512;

@end