//
//  Signature.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

public class Signature {
    
    public enum DigestType {
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        var algorithm: Algorithm {
            switch self {
            case .sha1: return .rsaSignatureDigestPKCS1v15SHA1
            case .sha224: return .rsaSignatureDigestPKCS1v15SHA224
            case .sha256: return .rsaSignatureDigestPKCS1v15SHA256
            case .sha384: return .rsaSignatureDigestPKCS1v15SHA384
            case .sha512: return .rsaSignatureDigestPKCS1v15SHA512
            }
        }
    }
    
    /// Data of the signature
    public let data: Data
    
    /// Creates a signature with data.
    ///
    /// - Parameter data: Data of the signature
    public init(data: Data) {
        self.data = data
    }
    
    /// Creates a signature with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded representation of the signature data.
    /// - Throws: SwiftyRSAError
    public convenience init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SwiftyRSAError.invalidBase64String
        }
        self.init(data: data)
    }
    
    /// Returns the base64 representation of the signature.
    public var base64String: String {
        return data.base64EncodedString()
    }
}
