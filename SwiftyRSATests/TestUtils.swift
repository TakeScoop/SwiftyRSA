//
//  TestUtils.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 4/1/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation
import SwiftyRSA

struct TestError: Error {
    let description: String
}

@objc public class TestUtils: NSObject {
    
    static let bundle = Bundle(for: TestUtils.self)
    
    static public func pemKeyString(name: String) -> String {
        let pubPath = bundle.path(forResource: name, ofType: "pem")!
        return (try! NSString(contentsOfFile: pubPath, encoding: String.Encoding.utf8.rawValue)) as String
    }
    
    static public func derKeyData(name: String) -> Data {
        let pubPath  = bundle.path(forResource: name, ofType: "der")!
        return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
    }
    
    static public func publicKey(name: String) throws -> PublicKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try PublicKey(pemEncoded: pemString)
    }
    
    static public func privateKey(name: String) throws -> PrivateKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try PrivateKey(pemEncoded: pemString)
    }
    
    static public func randomData(count: Int) -> Data {
        let bytes = [Int](repeating: 0, count: count).map { _ in UInt8(arc4random_uniform(256)) }
        let capacity = bytes.count * MemoryLayout<UInt8>.size
        let int8Bytes = UnsafeRawPointer(UnsafePointer<UInt8>(bytes))
        return Data(bytes: int8Bytes, count: capacity)
    }
}
