//
//  SwiftyRSATests.swift
//  SwiftyRSATests
//
//  Created by Loïs Di Qual on 7/2/15.
//  Copyright (c) 2015 Scoop. All rights reserved.
//

import UIKit
import XCTest
import SwiftyRSA

class SwiftyRSATests: XCTestCase {
    
    func testClassPEM() {
        let str = "ClearText"
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testClassDER() {
        let str = "ClearText"
        
        let pubData = TestUtils.derKeyData(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyDER: pubData)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssert(str == decrypted)
    }
    
    func testPEM() {
        let str = "ClearText"
        
        let rsa = SwiftyRSA()
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let pubKey    = try! rsa.publicKeyFromPEMString(pubString)
        
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        let privKey    = try! rsa.privateKeyFromPEMString(privString)
        
        let encrypted = try! rsa.encryptString(str, publicKey: pubKey)
        let decrypted = try! rsa.decryptString(encrypted, privateKey: privKey)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testDER() {
        let str = "ClearText"
        
        let rsa = SwiftyRSA()
        
        let pubData = TestUtils.derKeyData(name: "swiftyrsa-public")
        let pubKey  = try! rsa.publicKeyFromDERData(pubData)
        
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        let privKey    = try! rsa.privateKeyFromPEMString(privString)
        
        let encrypted = try! rsa.encryptString(str, publicKey: pubKey)
        let decrypted = try! rsa.decryptString(encrypted, privateKey: privKey)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testPEMHeaderless() {
        let str = "ClearText"
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public-headerless")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private-headerless")
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testLongString() {
        let str = [String](repeating: "a", count: 9999).joined(separator: "")
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testDataEncryptDecrypt() {
        let bytes = [UInt32](repeating: 0, count: 2048).map { _ in arc4random() }
        let capacity = bytes.count * MemoryLayout<UInt32>.size
        let int8Bytes = UnsafeRawPointer(UnsafePointer<UInt32>(bytes)).bindMemory(to: UInt8.self, capacity: capacity)
        let data = Data(bytes: int8Bytes, count: capacity)
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptData(data, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptData(encrypted, privateKeyPEM: privString)
        
        XCTAssertEqual(data, decrypted)
    }
    
    func testNoPaddingEncryptDecrypt() {
        let bytes = [UInt32](repeating: 0, count: 32).map { _ in arc4random() }
        let capacity = bytes.count * MemoryLayout<UInt32>.size
        let int8Bytes = UnsafeRawPointer(UnsafePointer<UInt32>(bytes)).bindMemory(to: UInt8.self, capacity: capacity)
        let data = Data(bytes: int8Bytes, count: capacity)
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptData(data, publicKeyPEM: pubString, padding: [])
        let encrypted2 = try! SwiftyRSA.encryptData(encrypted, publicKeyPEM: pubString, padding: [])
        
        XCTAssertEqual(encrypted.count, encrypted2.count)
        XCTAssertEqual(encrypted.count, 128)
        
        let decrypted1 = try! SwiftyRSA.decryptData(encrypted2, privateKeyPEM: privString, padding: [])
        let decrypted = try! SwiftyRSA.decryptData(decrypted1, privateKeyPEM: privString, padding: [])
        
        XCTAssertEqual(data, decrypted)
    }
    
    func testSignVerify() {
        
        
        let bytes = [UInt32](repeating: 0, count: 2048).map { _ in arc4random() }
        let capacity = bytes.count * MemoryLayout<UInt32>.size
        let int8Bytes = UnsafeRawPointer(UnsafePointer<UInt32>(bytes)).bindMemory(to: UInt8.self, capacity: capacity)
        let data = Data(bytes: int8Bytes, count: capacity)
        
        let testString = "Lorum Ipsum Ipso Facto Ad Astra Ixnay Onay Ayway"
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let pubData = TestUtils.derKeyData(name: "swiftyrsa-public")
        
        let rsa = SwiftyRSA()
        
        let pubKey = try! rsa.publicKeyFromPEMString(pubString)
        let privKey = try! rsa.privateKeyFromPEMString(privString)
        
        let hashingMethods: [SwiftyRSA.DigestType] = [.SHA1, .SHA224, .SHA256, .SHA384, .SHA512]
        
        for method in hashingMethods {
            let digestSignature = try! SwiftyRSA.signData(data, privateKeyPEM: privString, digestMethod: method)
            var result = SwiftyRSA.verifySignatureData(data, signature: digestSignature, publicKeyPEM: pubString, digestMethod: method)
            XCTAssertTrue(result.isSuccessful)
            
            let signatureString = try! SwiftyRSA.signString(testString, privateKeyPEM: privString, digestMethod: method)
            result = SwiftyRSA.verifySignatureString(testString, signature: signatureString, publicKeyPEM: pubString, digestMethod: method)
            XCTAssertTrue(result.isSuccessful)
                        
            result = SwiftyRSA.verifySignatureString(testString, signature: signatureString, publicKeyDER: pubData, digestMethod: method)
            XCTAssertTrue(result.isSuccessful)
        }
        
        let signature = try! SwiftyRSA.signData(data, privateKeyPEM: privString)
        
        var result = SwiftyRSA.verifySignatureData(data, signature: signature, publicKeyPEM: pubString)
        XCTAssertTrue(result.isSuccessful)
        
        result = SwiftyRSA.verifySignatureData(data, signature:  signature, publicKeyDER:  pubData)
        XCTAssertTrue(result.isSuccessful)
        
        let badBytes = [UInt32](repeating: 0, count: 16).map { _ in arc4random() }
        let badCapacity = badBytes.count * MemoryLayout<UInt32>.size
        let badInt8Bytes = UnsafeRawPointer(UnsafePointer<UInt32>(badBytes)).bindMemory(to: UInt8.self, capacity: capacity)
        let badData = Data(bytes: badInt8Bytes, count: badCapacity)
        
        result = SwiftyRSA.verifySignatureData(badData, signature:  signature, publicKeyPEM: pubString)
        XCTAssertFalse(result.isSuccessful)
        
        
        var digest = data.swiftyRSASHA1
        
        var digestSignature = try! rsa.signSHA1Digest(digest, privateKey: privKey)
        
        result = rsa.verifySHA1SignatureData(digest, signature: digestSignature, publicKey: pubKey)
        XCTAssertTrue(result.isSuccessful)
        
        digest = data.swiftyRSASHA224
        
        digestSignature = try! rsa.signDigest(digest, privateKey: privKey, digestMethod: .SHA224)
        
        result = rsa.verifySignatureData(digest, signature: digestSignature, publicKey: pubKey, digestMethod: .SHA224)
        XCTAssertTrue(result.isSuccessful)
        
        digest = data.swiftyRSASHA256
        
        digestSignature = try! rsa.signDigest(digest, privateKey: privKey, digestMethod: .SHA256)
        
        result = rsa.verifySignatureData(digest, signature: digestSignature, publicKey: pubKey, digestMethod: .SHA256)
        XCTAssertTrue(result.isSuccessful)
        
        digest = data.swiftyRSASHA384
        
        digestSignature = try! rsa.signDigest(digest, privateKey: privKey, digestMethod: .SHA384)
        
        result = rsa.verifySignatureData(digest, signature: digestSignature, publicKey: pubKey, digestMethod: .SHA384)
        XCTAssertTrue(result.isSuccessful)
        
        digest = data.swiftyRSASHA512
        
        digestSignature = try! rsa.signDigest(digest, privateKey: privKey, digestMethod: .SHA512)
        
        result = rsa.verifySignatureData(digest, signature: digestSignature, publicKey: pubKey, digestMethod: .SHA512)
        XCTAssertTrue(result.isSuccessful)
        
    }
    
    /// See also: multiple-keys-testcase.sh for the generation of this file
    func testReadingPublicKeysFromComplexPEMFileWorksCorrectly(){
        let input = TestUtils.pemKeyString(name: "multiple-keys-testcase")
        
        XCTAssertEqual(
            SwiftyRSA().publicKeysFromString(input).count,
            9
        )
    }
    
    func testReadingPublicKeysFromEmptyPEMFileReturnsEmptyArray(){
        XCTAssertEqual(
            SwiftyRSA().publicKeysFromString("").count,
            0
        )
    }
    
    func testReadingPublicKeysFromPrivateKeyPEMFileReturnsEmptyArray(){
        let input = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        XCTAssertEqual(
            SwiftyRSA().publicKeysFromString(input).count,
            0
        )
    }
}
