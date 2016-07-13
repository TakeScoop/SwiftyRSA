//
//  Wildfire.swift
//  SwiftyRSA
//
//  Created by Mark Hughes on 7/15/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import XCTest
import SwiftyRSA
import Security

public protocol SwiftyRSABackendProtocol {
    func generateHash(input: String, hashType: DigestType) -> String;
}

public class SecTransformBackend : NSObject, SwiftyRSABackendProtocol {
    public func generateHash(input: String, hashType: DigestType) -> String {
        // Total sham mock
        
        let response = "";
        
        return response;
    }
}

public class MockBackend : NSObject, SwiftyRSABackendProtocol {
    public func generateHash(input: String, hashType: DigestType) -> String {
        return "";
    }
}

protocol ConcreteBackendTests {
    func testSHA256Reference();
}

class ComposableTester {
    
}

class SecTransformBackendTest : XCTestCase, ConcreteBackendTests {
    func getInstance(){
        return SecTransformBackend()
    }
    
    func testSHA256Reference() {
        XCTAssert(
            
        )
    }
}
























class Wildfire: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }

}
