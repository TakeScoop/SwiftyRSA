//
//  EncryptDecryptTests.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest
import SwiftyRSA

class EncryptDecryptTests: XCTestCase {
    
    /// PKCS#1 v1.5 with 1024 bit RSA key can encrypt up to 117 bytes.
    let byteLimitForPKCS1 = 117
    /// PKCS#1 v2.1 with 1024 bit RSA key can encrypt up to 86 bytes for SHA-1.
    let byteLimitForOAEP = 86
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public") // swiftlint:disable:this force_try
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private") // swiftlint:disable:this force_try
    
    func test_simple() throws {
        let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
    
    func test_longString() throws {
        let str = [String](repeating: "a", count: 99).joined(separator: "")
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
    
    func test_randomBytes() throws {
        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
        
        XCTAssertEqual(decrypted.data, data)
    }
    
    // See https://github.com/TakeScoop/SwiftyRSA/issues/135
//    func test_noPadding() throws {
//
//        let data = TestUtils.randomData(count: 128)
//        let clearMessage = ClearMessage(data: data)
//        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: [])
//
//        let clearMessage2 = ClearMessage(data: encrypted.data)
//        let encrypted2 = try clearMessage2.encrypted(with: publicKey, algorithm: [])
//
//        XCTAssertEqual(data.count, encrypted.data.count)
//        XCTAssertEqual(data.count, encrypted2.data.count)
//
//        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: [])
//
//        XCTAssertEqual(decrypted.data, data)
//    }
    
    func test_OAEP() throws {
        let data = TestUtils.randomData(count: byteLimitForOAEP)
        let clearMessage = ClearMessage(data: data)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionOAEPSHA1)
        let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionOAEPSHA1)
        
        XCTAssertEqual(decrypted.data, data)
    }
    
    func test_keyReferences() throws {
        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)
        
        let newPublicKey = try PublicKey(reference: publicKey.reference)
        let newPrivateKey = try PrivateKey(reference: privateKey.reference)
        
        // Encrypt with old public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with old public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
    }
    
    func test_keyData() throws {
        
        let data = TestUtils.randomData(count: byteLimitForPKCS1)
        let clearMessage = ClearMessage(data: data)
        
        let newPublicKey = try PublicKey(data: try publicKey.data())
        let newPrivateKey = try PrivateKey(data: try privateKey.data())
        
        // Encrypt with old public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with old public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, algorithm: .rsaEncryptionPKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, algorithm: .rsaEncryptionPKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
    }
}
