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
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public") // swiftlint:disable:this force_try
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private") // swiftlint:disable:this force_try
    
    func test_simple() throws {
        let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
    
    func test_longString() throws {
        let str = [String](repeating: "a", count: 9999).joined(separator: "")
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
    
    func test_randomBytes() throws {
        let data = TestUtils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
        
        XCTAssertEqual(decrypted.data, data)
    }
    
    // See https://github.com/TakeScoop/SwiftyRSA/issues/135
//    func test_noPadding() throws {
//
//        let data = TestUtils.randomData(count: 128)
//        let clearMessage = ClearMessage(data: data)
//        let encrypted = try clearMessage.encrypted(with: publicKey, padding: [])
//
//        let clearMessage2 = ClearMessage(data: encrypted.data)
//        let encrypted2 = try clearMessage2.encrypted(with: publicKey, padding: [])
//
//        XCTAssertEqual(data.count, encrypted.data.count)
//        XCTAssertEqual(data.count, encrypted2.data.count)
//
//        let decrypted = try encrypted.decrypted(with: privateKey, padding: [])
//
//        XCTAssertEqual(decrypted.data, data)
//    }
    
    func test_OAEP() throws {
        let data = TestUtils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, padding: .OAEP)
        let decrypted = try encrypted.decrypted(with: privateKey, padding: .OAEP)
        
        XCTAssertEqual(decrypted.data, data)
    }
    
    func test_keyReferences() throws {
        let data = TestUtils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        
        let newPublicKey = try PublicKey(reference: publicKey.reference)
        let newPrivateKey = try PrivateKey(reference: privateKey.reference)
        
        // Encrypt with old public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with old public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
    }
    
    func test_keyData() throws {
        
        let data = TestUtils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        
        let newPublicKey = try PublicKey(data: try publicKey.data())
        let newPrivateKey = try PrivateKey(data: try privateKey.data())
        
        // Encrypt with old public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with old public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with old private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
        
        // Encrypt with new public key, decrypt with new private key
        do {
            let encrypted = try clearMessage.encrypted(with: newPublicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: newPrivateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
    }
}
