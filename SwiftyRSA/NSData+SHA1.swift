//
//  NSData+SHA1.swift
//  SwiftyRSA
//
//  Created by Paul Wilkinson on 15/04/2016.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation
import CommonCrypto

extension NSData {
    func SHA1() -> NSData {
        var digest = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
        
        CC_SHA1(self.bytes, CC_LONG(self.length), &digest)
        
        let digestData = NSData(bytes: digest, length: Int(CC_SHA1_DIGEST_LENGTH))
        
        return digestData
    }
}