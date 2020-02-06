//
//  Data+SHA.swift
//  SwiftyRSA iOS
//
//  Created by Rasid Ramazanov on 2/6/20.
//  Copyright © 2020 Scoop. All rights reserved.
//
//  SHA_X based`Data` extension.
//  exposed from from CommonCrypto-60118.50.1:
//  https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60118.50.1/include/CommonDigest.h.auto.html
//  References:
//   - https://www.agnosticdev.com/content/how-use-commoncrypto-apis-swift-5
//

import Foundation
import CommonCrypto

extension Data {
    
    /// Returns SHA 1 `Data`.
    func swiftyRSASHA1() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = withUnsafeBytes {
            CC_SHA1($0.baseAddress, UInt32(count), &digest)
        }
        return Data(digest)
    }
    
    /// Returns SHA 224 `Data`.
    func swiftyRSASHA224() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        _ = withUnsafeBytes {
            CC_SHA224($0.baseAddress, UInt32(count), &digest)
        }
        return Data(digest)
    }
    
    /// Returns SHA 256 `Data`.
    func swiftyRSASHA256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = withUnsafeBytes {
            CC_SHA256($0.baseAddress, UInt32(count), &digest)
        }
        return Data(digest)
    }
    
    /// Returns SHA 384 `Data`.
    func swiftyRSASHA384() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        _ = withUnsafeBytes {
            CC_SHA384($0.baseAddress, UInt32(count), &digest)
        }
        return Data(digest)
    }
    
    /// Returns SHA 512 `Data`.
    func swiftyRSASHA512() -> Data {
        /// #define CC_SHA512_DIGEST_LENGTH     32
        /// Creates an array of unsigned 8 bit integers that contains 32 zeros
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        /// CC_SHA512 performs digest calculation and places the result in the caller-supplied buffer for digest (md)
        /// Takes the `self` referenced value (const unsigned char *d)
        /// and hashes it into a reference to the digest parameter.
        _ = withUnsafeBytes {
            // CommonCrypto
            // extern unsigned char *CC_SHA512(const void *data, CC_LONG len, unsigned char *md)  -|
            // OpenSSL                                                                             |
            // unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)        <-|
            CC_SHA512($0.baseAddress, UInt32(count), &digest)
        }
        return Data(digest)
    }
    
}
