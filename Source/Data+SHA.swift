//
//  Data+SHA.swift
//  
//
//  Created by Joanna Bednarz on 02/10/2020.
//

import Foundation
import CommonCrypto
#if canImport(CryptoKit)
import CryptoKit
#endif

extension Data {
    
    func swiftyRSASHA1() -> Data {
        if #available(iOS 13.0, *) {
            return Data(CryptoKit.Insecure.SHA1.hash(data: self))
        } else {
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA1_DIGEST_LENGTH))
            withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
                _ = CC_SHA1(buffer.baseAddress, CC_LONG(count), &digest)
            }
            return Data(digest)
            
        }
    }
    
    func swiftyRSASHA224() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA224_DIGEST_LENGTH))
        withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            _ = CC_SHA224(buffer.baseAddress, CC_LONG(count), &digest)
        }
        return Data(digest)
    }
    
    func swiftyRSASHA256() -> Data {
        if #available(iOS 13.0, *) {
            return Data(CryptoKit.SHA256.hash(data: self))
        } else {
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA256_DIGEST_LENGTH))
            withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
                _ = CC_SHA256(buffer.baseAddress, CC_LONG(count), &digest)
            }
            return Data(digest)
        }
    }
    
    func swiftyRSASHA384() -> Data {
        if #available(iOS 13.0, *) {
            return Data(CryptoKit.SHA384.hash(data: self))
        } else {
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA384_DIGEST_LENGTH))
            withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
                _ = CC_SHA384(buffer.baseAddress, CC_LONG(count), &digest)
            }
            return Data(digest)
        }
    }
    
    func swiftyRSASHA512() -> Data {
        if #available(iOS 13.0, *) {
            return Data(CryptoKit.SHA512.hash(data: self))
        } else {
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA512_DIGEST_LENGTH))
            withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
                _ = CC_SHA512(buffer.baseAddress, CC_LONG(count), &digest)
            }
            return Data(digest)
        }
    }
    
}
