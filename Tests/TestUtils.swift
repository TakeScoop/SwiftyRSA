//
//  TestUtils.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 4/1/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation
import SwiftyRSA
import XCTest

struct TestError: Error {
    let description: String
}

// swiftlint:disable force_try
// swiftlint:disable force_unwrapping
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
    
    @nonobjc
    static public func publicKey(name: String) throws -> PublicKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try PublicKey(pemEncoded: pemString)
    }
    
    @objc(publicKeyWithName:error:)
    static public func _objc_publicKey(name: String) throws -> _objc_PublicKey { // swiftlint:disable:this identifier_name
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try _objc_PublicKey(pemEncoded: pemString)
    }
    
    @nonobjc
    static public func privateKey(name: String) throws -> PrivateKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try PrivateKey(pemEncoded: pemString)
    }
    
    @objc(privateKeyWithName:error:)
    static public func _objc_privateKey(name: String) throws -> _objc_PrivateKey { // swiftlint:disable:this identifier_name
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try _objc_PrivateKey(pemEncoded: pemString)
    }
    
    @objc
    static public func randomData(count: Int) -> Data {
        var randomBytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &randomBytes)
        if status != errSecSuccess {
             XCTFail("Couldn't create random data")
        }
        return Data(bytes: randomBytes)
    }
    
    static func assertThrows(type: SwiftyRSAError, file: StaticString = #file, line: UInt = #line, block: () throws ->  Void) {
        do {
            try block()
            XCTFail("The line above should fail", file: file, line: line)
        } catch {
            guard let swiftyRsaError = error as? SwiftyRSAError else {
                return XCTFail("Error is not a SwiftyRSAError", file: file, line: line)
            }
            XCTAssertEqual(swiftyRsaError, type, file: file, line: line)
        }
    }
}
// swiftlint:enable force_try
// swiftlint:enable force_unwrapping

extension SwiftyRSAError: Equatable {
    public static func == (lhs: SwiftyRSAError, rhs: SwiftyRSAError) -> Bool {
        switch (lhs, rhs) {
        case
            (.pemDoesNotContainKey, .pemDoesNotContainKey),
            (.keyRepresentationFailed, .keyRepresentationFailed),
            (.keyAddFailed, .keyAddFailed),
            (.keyCopyFailed, .keyCopyFailed),
            (.tagEncodingFailed, .tagEncodingFailed),
            (.asn1ParsingFailed, .asn1ParsingFailed),
            (.invalidAsn1RootNode, .invalidAsn1RootNode),
            (.invalidAsn1Structure, .invalidAsn1Structure),
            (.invalidBase64String, .invalidBase64String),
            (.chunkDecryptFailed, .chunkDecryptFailed),
            (.chunkEncryptFailed, .chunkEncryptFailed),
            (.stringToDataConversionFailed, .stringToDataConversionFailed),
            (.dataToStringConversionFailed, .dataToStringConversionFailed),
            (.invalidDigestSize, .invalidDigestSize),
            (.signatureCreateFailed, .signatureCreateFailed),
            (.signatureVerifyFailed, .signatureVerifyFailed),
            (.pemFileNotFound, .pemFileNotFound),
            (.derFileNotFound, .derFileNotFound),
            (.notAPublicKey, .notAPublicKey),
            (.notAPrivateKey, .notAPrivateKey):
            return true
        default:
            return false
        }
    }
}
