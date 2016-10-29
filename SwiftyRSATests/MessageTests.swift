//
//  MessageTests.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest
import SwiftyRSA

class ClearMessageTests: XCTestCase {
    
    func test_initWithData() {
        let data = TestUtils.randomData(count: 1024)
        _ = ClearMessage(data: data)
        XCTAssertTrue(true, "All good")
    }
    
    func test_initWithBase64String() {
        let data = TestUtils.randomData(count: 1024)
        let base64String = data.base64EncodedString()
        let message = try? ClearMessage(base64Encoded: base64String)
        XCTAssertNotNil(message)
    }
    
    func test_initWithString() {
        let str = "Clear Text"
        let message = try? ClearMessage(string: str, using: .utf8)
        XCTAssertNotNil(message)
    }
    
    func test_string() throws {
        let str = "Clear Text"
        let message = try ClearMessage(string: str, using: .utf8)
        XCTAssertEqual(try? message.string(encoding: .utf8), str)
    }
    
    func test_base64String() throws {
        let data = TestUtils.randomData(count: 1024)
        let base64String = data.base64EncodedString()
        let message = try? ClearMessage(base64Encoded: base64String)
        XCTAssertEqual(message?.base64String, base64String)
    }
}

class EncryptedMessageTests: XCTestCase {
    func test_initWithData() {
        let data = TestUtils.randomData(count: 1024)
        _ = EncryptedMessage(data: data)
        XCTAssertTrue(true, "All good")
    }
    
    func test_initWithBase64String() {
        let data = TestUtils.randomData(count: 1024)
        let base64String = data.base64EncodedString()
        let message = try? EncryptedMessage(base64Encoded: base64String)
        XCTAssertNotNil(message)
    }
    
    func test_base64Encoded() throws {
        let data = TestUtils.randomData(count: 1024)
        let base64String = data.base64EncodedString()
        let message = try? EncryptedMessage(base64Encoded: base64String)
        XCTAssertEqual(message?.base64String, base64String)
    }
}
