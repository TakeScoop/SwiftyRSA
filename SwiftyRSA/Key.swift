//
//  Key.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

typealias PEMString = String

public protocol Key {
    init(data: Data) throws
}

@objc public class PublicKey: NSObject, Key {
    
    /// Reference to the key within the keychain
    public let reference: SecKey
    
    /// Tag of the key within the keychain
    public let tag: String
    
    /// Data of the public key without a x509 header.
    /// Since SwiftyRSA strips public key headers, `key.data` might be different then `key.dataWithoutHeader`.
    public let dataWithoutHeader: Data
    
    /// Data of the public key as provided when creating the key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public let data: Data
    
    /// Creates a public with a RSA public key data.
    ///
    /// - Parameter data: Public key data
    /// - Throws: SwiftyRSAError
    required public init(data: Data) throws {
        
        tag = UUID().uuidString
        
        let dataWithoutHeader = try SwiftyRSA.stripPublicKeyHeader(keyData: data)
        self.dataWithoutHeader = dataWithoutHeader
        self.data = data
        
    	reference = try SwiftyRSA.addKey(dataWithoutHeader, isPublic: true, tag: tag)
    }
    
    /// Creates a public key with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded public key data
    /// - Throws: SwiftyRSAError
    public convenience init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
            throw SwiftyRSAError(message: "Couldn't decode base 64 string")
        }
        try self.init(data: data)
    }
    
    /// Creates a public key with a PEM string.
    ///
    /// - Parameter pemString: PEM-encoded public key string
    /// - Throws: SwiftyRSAError
    public convenience init(pemEncoded pemString: String) throws {
        let base64String = try SwiftyRSA.base64String(pemEncoded: pemString)
        try self.init(base64Encoded: base64String)
    }
    
    /// Creates a public key with a PEM file.
    ///
    /// - Parameters:
    ///   - pemName: Name of the PEM file
    ///   - bundle: Bundle in which to look for the PEM file. Defaults to the main bundle.
    /// - Throws: SwiftyRSAError
    public convenience init(pemNamed pemName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: pemName, ofType: "pem") else {
            throw SwiftyRSAError(message: "Couldn't find a PEM file named '\(pemName)'")
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
    public convenience init(derNamed derName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: derName, ofType: "der") else {
            throw SwiftyRSAError(message: "Couldn't find a DER file named '\(derName)'")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try self.init(data: data)
    }
    
    static let publicKeyRegex: NSRegularExpression? = {
        let publicKeyRegex = "(-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----)"
        return try? NSRegularExpression(pattern: publicKeyRegex, options: .dotMatchesLineSeparators)
    }()
    
    /// Takes an input string, scans for public key sections, and then returns a PublicKey for any valid keys found
    /// - This method scans the file for public key armor - if no keys are found, an empty array is returned
    /// - Each public key block found is "parsed" by `publicKeyFromPEMString()`
	/// - should that method throw, the error is _swallowed_ and not rethrown
    ///
    /// - parameter pemString: The string to use to parse out values
    ///
    /// - returns: An array of `PublicKey` objects
    public static func publicKeys(pemEncoded pemString: String) -> [PublicKey] {
        
        // If our regexp isn't valid, or the input string is empty, we can't move forward…
        guard let publicKeyRegexp = publicKeyRegex, pemString.characters.count > 0 else {
            return []
        }
        
        let all = NSRange(
            location: 0,
            length: pemString.characters.count
        )
        
        let matches = publicKeyRegexp.matches(
            in: pemString,
            options: NSRegularExpression.MatchingOptions(rawValue: 0),
            range: all
        )
        
        let keys = matches.flatMap { result -> PublicKey? in
            let match = result.rangeAt(1)
            let start = pemString.characters.index(pemString.startIndex, offsetBy: match.location)
            let end = pemString.characters.index(start, offsetBy: match.length)
            
            let range = Range<String.Index>(start..<end)
            
            let thisKey = pemString[range]
            
            return try? PublicKey(pemEncoded: thisKey)
        }
        
        return keys
    }
    
    deinit {
        SwiftyRSA.removeKey(tag: tag)
    }
}

@objc public class PrivateKey: NSObject, Key {
    
    /// Reference to the key within the keychain
    public let reference: SecKey
    
    /// Tag of the key within the keychain
    public let tag: String
    
    /// Original data of the private key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public let data: Data
    
    /// Creates a private key with a RSA public key data.
    ///
    /// - Parameter data: Private key data
    /// - Throws: SwiftyRSAError
    required public init(data: Data) throws {
        self.data = data
        tag = UUID().uuidString
        reference = try SwiftyRSA.addKey(data, isPublic: false, tag: tag)
    }
    
    /// Creates a private key with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded private key data
    /// - Throws: SwiftyRSAError
    public convenience init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
            throw SwiftyRSAError(message: "Couldn't decode base 64 string")
        }
        try self.init(data: data)
    }
    
    /// Creates a private key with a PEM string.
    ///
    /// - Parameter pemString: PEM-encoded private key string
    /// - Throws: SwiftyRSAError
    public convenience init(pemEncoded pemString: String) throws {
        let base64String = try SwiftyRSA.base64String(pemEncoded: pemString)
        try self.init(base64Encoded: base64String)
    }
    
    /// Creates a private key with a PEM file.
    ///
    /// - Parameters:
    ///   - pemName: Name of the PEM file
    ///   - bundle: Bundle in which to look for the PEM file. Defaults to the main bundle.
    /// - Throws: SwiftyRSAError
    public convenience init(pemNamed pemName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: pemName, ofType: "pem") else {
            throw SwiftyRSAError(message: "Couldn't find a PEM file named '\(pemName)'")
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
    public convenience init(derNamed derName: String, in bundle: Bundle = Bundle.main) throws {
        guard let path = bundle.path(forResource: derName, ofType: "der") else {
            throw SwiftyRSAError(message: "Couldn't find a DER file named '\(derName)'")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try self.init(data: data)
    }
    
    deinit {
        SwiftyRSA.removeKey(tag: tag)
    }
}
