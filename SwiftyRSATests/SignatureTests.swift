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
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public") // swiftlint:disable:this force_try
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private") // swiftlint:disable:this force_try
    
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
    
    func test_base64String() throws {
        let data = TestUtils.randomData(count: 8192)
        let message = ClearMessage(data: data)
        let signature = try message.signed(with: privateKey, digestType: .sha1)
        XCTAssertEqual(signature.base64String, signature.data.base64EncodedString())
    }
    
    func test_initWithBase64String() throws {
        let data = TestUtils.randomData(count: 128)
        _ = try Signature(base64Encoded: data.base64EncodedString())
    }
    
    func test_initWithData() throws {
        let data = TestUtils.randomData(count: 128)
        _ = Signature(data: data)
    }
}
