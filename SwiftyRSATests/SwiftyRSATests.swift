//
//  SwiftyRSATests.swift
//  SwiftyRSATests
//
//  Created by Loïs Di Qual on 7/2/15.
//  Copyright (c) 2015 Scoop. All rights reserved.
//

import UIKit
import XCTest

class SwiftyRSATests: XCTestCase {
    
    func testClassPEM() {
        let str = "ClearText"
        
        let bundle = NSBundle(forClass: self.dynamicType)
        
        let pubPath   = bundle.pathForResource("swiftyrsa-public", ofType: "pem")!
        let pubString = (try! NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding)) as String
        
        let privPath   = bundle.pathForResource("swiftyrsa-private", ofType: "pem")!
        let privString = (try! NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding)) as String
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyPEM: pubString)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssert(str == decrypted)
    }
    
    func testClassDER() {
        let str = "ClearText"
        
        let bundle = NSBundle(forClass: self.dynamicType)
        
        let pubPath  = bundle.pathForResource("swiftyrsa-public", ofType: "der")!
        let pubData = NSData(contentsOfFile: pubPath)!
        
        let privPath   = bundle.pathForResource("swiftyrsa-private", ofType: "pem")!
        let privString = (try! NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding)) as String
        
        let encrypted = try! SwiftyRSA.encryptString(str, publicKeyDER: pubData)
        let decrypted = try! SwiftyRSA.decryptString(encrypted, privateKeyPEM: privString)
        
        XCTAssert(str == decrypted)
    }
    
    func testPEM() {
        let str = "ClearText"
        
        let bundle = NSBundle(forClass: self.dynamicType)
        
        let rsa = SwiftyRSA()
        
        let pubPath   = bundle.pathForResource("swiftyrsa-public", ofType: "pem")!
        let pubString = (try! NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding)) as String
        let pubKey    = try! rsa.publicKeyFromPEMString(pubString)
        
        let privPath   = bundle.pathForResource("swiftyrsa-private", ofType: "pem")!
        let privString = (try! NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding)) as String
        let privKey    = try! rsa.privateKeyFromPEMString(privString)
        
        let encrypted = try! rsa.encryptString(str, publicKey: pubKey)
        let decrypted = try! rsa.decryptString(encrypted, privateKey: privKey)
        
        XCTAssert(str == decrypted)
    }
    
    func testDER() {
        let str = "ClearText"
        
        let bundle = NSBundle(forClass: self.dynamicType)
        
        let rsa = SwiftyRSA()
        
        let pubPath = bundle.pathForResource("swiftyrsa-public", ofType: "der")!
        let pubData = NSData(contentsOfFile: pubPath)!
        let pubKey  = try! rsa.publicKeyFromDERData(pubData)
        
        let privPath   = bundle.pathForResource("swiftyrsa-private", ofType: "pem")!
        let privString = (try! NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding)) as String
        let privKey    = try! rsa.privateKeyFromPEMString(privString)
        
        let encrypted = try! rsa.encryptString(str, publicKey: pubKey)
        let decrypted = try! rsa.decryptString(encrypted, privateKey: privKey)
        
        XCTAssert(str == decrypted)
    }
}
