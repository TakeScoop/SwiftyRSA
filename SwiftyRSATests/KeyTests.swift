//
//  KeyTests.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest
import SwiftyRSA

class PublicKeyTests: XCTestCase {
    
    let bundle = Bundle(for: PublicKeyTests.self)
    
    func test_initWithData() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail()
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try? PublicKey(data: data)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithBase64String() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-base64", ofType: "txt") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithBase64StringWhichContainsNewLines() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-base64-newlines", ofType: "txt") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMName() throws {
        let message = try? PublicKey(pemNamed: "swiftyrsa-public", in: Bundle(for: TestUtils.self))
        XCTAssertNotNil(message)
    }
    
    func test_initWithDERName() throws {
        let message = try? PublicKey(pemNamed: "swiftyrsa-public", in: Bundle(for: TestUtils.self))
        XCTAssertNotNil(message)
    }
    
    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-headerless", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_publicKeysFromComplexPEMFileWorksCorrectly() {
        let input = TestUtils.pemKeyString(name: "multiple-keys-testcase")
        let keys = PublicKey.publicKeys(pemEncoded: input)
        XCTAssertEqual(keys.count, 9)
    }
    
    func test_publicKeysFromEmptyPEMFileReturnsEmptyArray() {
        let keys = PublicKey.publicKeys(pemEncoded: "")
        XCTAssertEqual(keys.count, 0)
    }
    
    func test_publicKeysFromPrivateKeyPEMFileReturnsEmptyArray() {
        let input = TestUtils.pemKeyString(name: "swiftyrsa-private")
        let keys = PublicKey.publicKeys(pemEncoded: input)
        XCTAssertEqual(keys.count, 0)
    }
}

class PrivateKeyTests: XCTestCase {
    
    let bundle = Bundle(for: PublicKeyTests.self)
    
    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? PrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }
    
    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private-headerless", ofType: "pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? PrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }
    
    func test_initWithPEMName() throws {
        let message = try? PrivateKey(pemNamed: "swiftyrsa-private", in: Bundle(for: TestUtils.self))
        XCTAssertNotNil(message)
    }
    
    func test_initWithDERName() throws {
        let message = try? PrivateKey(pemNamed: "swiftyrsa-private", in: Bundle(for: TestUtils.self))
        XCTAssertNotNil(message)
    }
}
