//
//  SignatureTests.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest
import SwiftyRSA

class SignatureTests: XCTestCase {
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public")
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private")
    
    func test_allDigestTypes() throws {
        
        let digestTypes: [Signature.DigestType] = [.sha1, .sha224, .sha256, .sha384, .sha512]
        
        for digestType in digestTypes {
            let data = TestUtils.randomData(count: 8192)
            let message = ClearMessage(data: data)
            let signature = try message.signed(with: privateKey, digestType: digestType)
            let isSuccessful = try message.verify(with: publicKey, signature: signature, digestType: digestType)
            XCTAssertTrue(isSuccessful)
        }
    }
}
