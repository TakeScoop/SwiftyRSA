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
    
    func testPEM() {
        let str = "ClearText"
        
        let bundle = NSBundle(forClass: self.dynamicType)
        
        let rsa = SwiftyRSA()
        
        let pubPath   = bundle.pathForResource("swiftyrsa-public", ofType: "pem")!
        let pubString = NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding, error: nil)! as String
        let pubKey    = rsa.publicKeyFromPEMString(pubString)!
        
        let privPath   = bundle.pathForResource("swiftyrsa-private", ofType: "pem")!
        let privString = NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding, error: nil)! as String
        let privKey    = rsa.privateKeyFromPEMString(privString)!
        
        let encrypted = rsa.encryptString(str, publicKey: pubKey)!
        let decrypted = rsa.decryptData(encrypted, privateKey: privKey)!
        
        XCTAssert(str == decrypted)
    }
    
    func testDER() {
        let str = "ClearText"
        
        let bundle = NSBundle(forClass: self.dynamicType)
        
        let rsa = SwiftyRSA()
        
        let pubPath = bundle.pathForResource("swiftyrsa-public", ofType: "der")!
        let pubData = NSData(contentsOfFile: pubPath)!
        let pubKey  = rsa.publicKeyFromDERData(pubData)!
        
        let privPath   = bundle.pathForResource("swiftyrsa-private", ofType: "pem")!
        let privString = NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding, error: nil)! as String
        let privKey    = rsa.privateKeyFromPEMString(privString)!
        
        let encrypted = rsa.encryptString(str, publicKey: pubKey)!
        let decrypted = rsa.decryptData(encrypted, privateKey: privKey)!
        
        XCTAssert(str == decrypted)
    }
}
