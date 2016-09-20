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

extension Key {
    public init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SwiftyRSAError(message: "Couldn't decode base 64 string")
        }
        try self.init(data: data)
    }
    
    public init(pemEncoded pemString: String) throws {
        let lines = pemString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        
        guard lines.count != 0 else {
            throw SwiftyRSAError(message: "Couldn't get data from PEM key: no data available after stripping headers")
        }
        
        let base64String = lines.joined(separator: "")
        
        try self.init(base64Encoded: base64String)
    }
}

public class PublicKey: Key {
    
    let reference: SecKey
    let tag: String
    
    required public init(data: Data) throws {
        tag = UUID().uuidString
        let data = try SwiftyRSA.stripPublicKeyHeader(keyData: data)
    	reference = try SwiftyRSA.addKey(data, isPublic: true, tag: tag)
    }
    
    static let publicKeyRegex : NSRegularExpression? = {
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

public class PrivateKey: Key {
    
    let reference: SecKey
    let tag: String
    
    required public init(data: Data) throws {
        tag = UUID().uuidString
        reference = try SwiftyRSA.addKey(data, isPublic: false, tag: tag)
    }
    
    deinit {
        SwiftyRSA.removeKey(tag: tag)
    }
}
