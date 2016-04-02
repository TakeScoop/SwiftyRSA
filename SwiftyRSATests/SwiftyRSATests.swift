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
        
        let rsa = SwiftyRSA()
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public-headerless")
        let pubKey    = try! rsa.publicKeyFromPEMString(pubString)
        
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private-headerless")
        let privKey    = try! rsa.privateKeyFromPEMString(privString)
        
        let encrypted = try! rsa.encryptString(str, publicKey: pubKey)
        let decrypted = try! rsa.decryptString(encrypted, privateKey: privKey)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testLongString() {
        let str = [String](count: 9999, repeatedValue: "a").joinWithSeparator("")
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssertEqual(str, decrypted)
    }
    
    func testDataEncryptDecrypt() {
        let bytes = [UInt32](count: 2048, repeatedValue: 0).map { _ in arc4random() }
        let data = NSData(bytes: bytes, length: bytes.count * sizeof(UInt32))
        
        let pubString = TestUtils.pemKeyString(name: "swiftyrsa-public")
        let privString = TestUtils.pemKeyString(name: "swiftyrsa-private")
        
        let encrypted = try! SwiftyRSA.encryptData(data, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptData(encrypted, privateKeyPEM: privString)
        
        XCTAssertEqual(data, decrypted)
    }
}
