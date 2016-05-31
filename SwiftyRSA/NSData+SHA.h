//
//  NSData_SHA1.h
//  SwiftyRSA
//
//  Created by Paul Wilkinson on 19/04/2016.
//  Copyright © 2016 Scoop. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NSData_SwiftyRSASHA)

- (nonnull NSData*) SwiftyRSASHA1;
- (nonnull NSData*) SwiftyRSASHA224;
- (nonnull NSData*) SwiftyRSASHA256;
- (nonnull NSData*) SwiftyRSASHA384;
- (nonnull NSData*) SwiftyRSASHA512;

@end