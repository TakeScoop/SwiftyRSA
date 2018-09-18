//
//  KeyTests.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest

// Using @testable here so we can call `SwiftyRSA.generateRSAKeyPair(sizeInBits:applyUnitTestWorkaround)`
@testable import SwiftyRSA

class PublicKeyTests: XCTestCase {
    
    let bundle = Bundle(for: PublicKeyTests.self)
    
    func test_initWithReference() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try PublicKey(data: data)
        let newPublicKey = try? PublicKey(reference: publicKey.reference)
        XCTAssertNotNil(newPublicKey)
    }
    
    func test_initWithReference_failsWithPrivateKey() throws {
        
        // We can't do key reference checking on iOS 8/9
        guard #available(iOS 10.0, *) else {
            return
        }
        
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try PrivateKey(pemEncoded: str)
        
        TestUtils.assertThrows(type: SwiftyRSAError.notAPublicKey) {
            _ = try PublicKey(reference: privateKey.reference)
        }
    }
    
    func test_initWithData() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try? PublicKey(data: data)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithBase64String() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-base64", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithBase64StringWhichContainsNewLines() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-base64-newlines", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(base64Encoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let publicKey = try? PublicKey(pemEncoded: str)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMName() throws {
        let publicKey = try? PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithDERName() throws {
        let publicKey = try? PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        XCTAssertNotNil(publicKey)
    }
    
    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-public-headerless", ofType: "pem") else {
            return XCTFail("file not found in bundle")
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
    
    func test_data() throws {
        
        // With header
        do {
            guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
                return XCTFail("file not found in bundle")
            }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let publicKey = try PublicKey(data: data)
            
            guard let dataFromKeychain = try? publicKey.data() else {
                return XCTFail("file not found in bundle")
            }
            
            XCTAssertNotEqual(dataFromKeychain, data)
            XCTAssertEqual(publicKey.originalData, data)
        }
        
        // Headerless
        do {
            guard let path = bundle.path(forResource: "swiftyrsa-public-headerless", ofType: "pem") else {
                return XCTFail("file not found in bundle")
            }
            let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
            let publicKey = try PublicKey(pemEncoded: str)
            XCTAssertNotNil(publicKey.originalData)
            XCTAssertNotNil(try? publicKey.data())
        }
    }
    
    func test_pemString() throws {
        let publicKey = try PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        let pemString = try publicKey.pemString()
        let newPublicKey = try PublicKey(pemEncoded: pemString)
        XCTAssertNotNil(newPublicKey)
        XCTAssertEqual(try? publicKey.data(), try? newPublicKey.data())
    }
    
    func test_base64String() throws {
        let publicKey = try PublicKey(pemNamed: "swiftyrsa-public", in: bundle)
        let base64String = try publicKey.base64String()
        let newPublicKey = try PublicKey(base64Encoded: base64String)
        XCTAssertNotNil(newPublicKey)
        XCTAssertEqual(try? publicKey.data(), try? newPublicKey.data())
    }
}

class PrivateKeyTests: XCTestCase {
    
    let bundle = Bundle(for: PublicKeyTests.self)
    
    func test_initWithReference() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try PrivateKey(pemEncoded: str)
        
        let newPrivateKey = try? PrivateKey(reference: privateKey.reference)
        XCTAssertNotNil(newPrivateKey)
    }
    
    func test_initWithReference_failsWithPublicKey() throws {
        
        // We can't do key reference checking on iOS 8/9
        guard #available(iOS 10.0, *) else {
            return
        }
        
        guard let path = bundle.path(forResource: "swiftyrsa-public", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try PublicKey(data: data)
        
        TestUtils.assertThrows(type: SwiftyRSAError.notAPrivateKey) {
            _ = try PrivateKey(reference: publicKey.reference)
        }
    }
    
    func test_initWithPEMString() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "pem") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try? PrivateKey(pemEncoded: str)
        XCTAssertNotNil(privateKey)
    }
    
    func test_initWithPEMStringHeaderless() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private-headerless", ofType: "pem") else {
            return XCTFail("file not found in bundle")
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
    
    func test_data() throws {
        guard let path = bundle.path(forResource: "swiftyrsa-private", ofType: "der") else {
            return XCTFail("file not found in bundle")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let publicKey = try PrivateKey(data: data)
        XCTAssertEqual(try? publicKey.data(), data)
    }
    
    func test_pemString() throws {
        let privateKey = try PrivateKey(pemNamed: "swiftyrsa-private", in: bundle)
        let pemString = try privateKey.pemString()
        let newPrivateKey = try PrivateKey(pemEncoded: pemString)
        XCTAssertNotNil(newPrivateKey)
        XCTAssertEqual(try? privateKey.data(), try? newPrivateKey.data())
    }
    
    func test_base64String() throws {
        let privateKey = try PrivateKey(pemNamed: "swiftyrsa-private", in: bundle)
        let base64String = try privateKey.base64String()
        let newPrivateKey = try PrivateKey(base64Encoded: base64String)
        XCTAssertEqual(try? privateKey.data(), try? newPrivateKey.data())
    }
    
    func test_headerAndOctetString() throws {
        _ = try PrivateKey(pemNamed: "swiftyrsa-private-header-octetstring", in: bundle)
    }
    
    func test_generateKeyPair() throws {
        
        guard #available(iOS 10.0, watchOS 3.0, tvOS 10.0, *) else {
            return
        }
        
        let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: 2048, applyUnitTestWorkaround: true)
        
        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA512
        guard SecKeyIsAlgorithmSupported(keyPair.privateKey.reference, .decrypt, algorithm) else {
            XCTFail("Key cannot be used for decryption")
            return
        }
        
        guard SecKeyIsAlgorithmSupported(keyPair.publicKey.reference, .encrypt, algorithm) else {
            XCTFail("Key cannot be used for encryption")
            return
        }
        
        let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        
        let encrypted = try clearMessage.encrypted(with: keyPair.publicKey, padding: .PKCS1)
        let decrypted = try encrypted.decrypted(with: keyPair.privateKey, padding: .PKCS1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
}
