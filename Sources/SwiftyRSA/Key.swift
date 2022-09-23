//
//  Key.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation
import Security

public protocol Key: AnyObject {
    
    var reference: SecKey { get }
    var originalData: Data? { get }
    
    init(data: Data) throws
    init(reference: SecKey) throws
    init(base64Encoded base64String: String) throws
    init(pemEncoded pemString: String) throws
    init(pemNamed pemName: String, in bundle: Bundle) throws
    init(derNamed derName: String, in bundle: Bundle) throws
    
    func pemString() throws -> String
    func data() throws -> Data
    func base64String() throws -> String
}

public extension Key {
    
    /// Returns a Base64 representation of the public key.
    ///
    /// - Returns: Data of the key, Base64-encoded
    /// - Throws: SwiftyRSAError
    func base64String() throws -> String {
        return try data().base64EncodedString()
    }
    
    func data() throws -> Data {
        return try SwiftyRSA.data(forKeyReference: reference)
    }
    
    /// Creates a public key with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded public key data
    /// - Throws: SwiftyRSAError
    init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
            throw SwiftyRSAError.invalidBase64String
        }
        try self.init(data: data)
    }
    
    /// Creates a public key with a PEM string.
    ///
    /// - Parameter pemString: PEM-encoded public key string
    /// - Throws: SwiftyRSAError
    init(pemEncoded pemString: String) throws {
        let base64String = try SwiftyRSA.base64String(pemEncoded: pemString)
        try self.init(base64Encoded: base64String)
    }
    
    /// Creates a public key with a PEM file.
    ///
    /// - Parameters:
    ///   - pemName: Name of the PEM file
    ///   - bundle: Bundle in which to look for the PEM file. Defaults to the main bundle.
    /// - Throws: SwiftyRSAError
    init(pemNamed pemName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: pemName, ofType: "pem") else {
            throw SwiftyRSAError.pemFileNotFound(name: pemName)
        }
        let keyString = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        try self.init(pemEncoded: keyString)
    }
    
    /// Creates a private key with a DER file.
    ///
    /// - Parameters:
    ///   - derName: Name of the DER file
    ///   - bundle: Bundle in which to look for the DER file. Defaults to the main bundle.
    /// - Throws: SwiftyRSAError
    init(derNamed derName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: derName, ofType: "der") else {
            throw SwiftyRSAError.derFileNotFound(name: derName)
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try self.init(data: data)
    }
}
