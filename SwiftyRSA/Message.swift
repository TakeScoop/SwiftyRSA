//
//  Message.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 9/19/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

@objc public class VerificationResult: NSObject {
    public let isSuccessful: Bool
    init(isSuccessful: Bool) {
        self.isSuccessful = isSuccessful
    }
}

public protocol Message {
    var data: Data { get }
    var base64String: String { get }
    init(data: Data)
}

@objc public class EncryptedMessage: NSObject, Message {
    
    /// Data of the message
    public let data: Data
    
    /// Base64-encoded string of the message data
    public var base64String: String {
        return data.base64EncodedString()
    }
    
    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    public required init(data: Data) {
        self.data = data
    }
    
    /// Creates an encrypted message with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded data of the encrypted message
    /// - Throws: SwiftyRSAError
    public convenience init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SwiftyRSAError(message: "Couldn't convert base 64 encoded string ")
        }
        self.init(data: data)
    }
    
    /// Decrypts an encrypted message with a private key and returns a clear message.
    ///
    /// - Parameters:
    ///   - key: Private key to decrypt the mssage with
    ///   - padding: Padding to use during the decryption
    /// - Returns: Clear message
    /// - Throws: SwiftyRSAError
    public func decrypted(with key: PrivateKey, padding: Padding) throws -> ClearMessage {
        let blockSize = SecKeyGetBlockSize(key.reference)
        
        var encryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&encryptedDataAsArray, length: data.count)
        
        var decryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < encryptedDataAsArray.count {
            
            let idxEnd = min(idx + blockSize, encryptedDataAsArray.count)
            let chunkData = [UInt8](encryptedDataAsArray[idx..<idxEnd])
            
            var decryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var decryptedDataLength = blockSize
            
            let status = SecKeyDecrypt(key.reference, padding, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            guard status == noErr else {
                throw SwiftyRSAError(message: "Couldn't decrypt chunk at index \(idx)")
            }
            
            decryptedDataBytes += [UInt8](decryptedDataBuffer[0..<decryptedDataLength])
            
            idx += blockSize
        }
        
        let decryptedData = Data(bytes: UnsafePointer<UInt8>(decryptedDataBytes), count: decryptedDataBytes.count)
        return ClearMessage(data: decryptedData)
    }
}

@objc public class ClearMessage: NSObject, Message {
    
    /// Data of the message
    public let data: Data
    
    /// Base64-encoded string of the message data
    public var base64String: String {
        return data.base64EncodedString()
    }
    
    /// Creates a clear message with data.
    ///
    /// - Parameter data: Data of the clear message
    public required init(data: Data) {
        self.data = data
    }
    
    /// Creates a clear message from a string, with the specified encoding.
    ///
    /// - Parameters:
    ///   - string: String value of the clear message
    ///   - encoding: Encoding to use to generate the clear data
    /// - Throws: SwiftyRSAError
    @nonobjc
    public convenience init(string: String, using encoding: String.Encoding) throws {
        guard let data = string.data(using: encoding) else {
            throw SwiftyRSAError(message: "Couldn't convert string to data using specified encoding")
        }
        self.init(data: data)
    }
    
    /// Creates a clear message from a string, with the specified encoding.
    ///
    /// - Parameters:
    ///   - string: String value of the clear message
    ///   - rawEncoding: Encoding to use to generate the clear data
    /// - Throws: SwiftyRSAError
    @objc
    public convenience init(string: String, using rawEncoding: UInt) throws {
        let encoding = String.Encoding(rawValue: rawEncoding)
        try self.init(string: string, using: encoding)
    }
    
    /// Creates a clear message from a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded string of the message data
    /// - Throws: SwiftyRSAError
    public convenience init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw SwiftyRSAError(message: "Couldn't convert base 64 encoded string ")
        }
        self.init(data: data)
    }
    
    /// Returns the string representation of the clear message using the specified
    /// string encoding.
    ///
    /// - Parameter encoding: Encoding to use during the string conversion
    /// - Returns: String representation of the clear message
    /// - Throws: SwiftyRSAError
    public func string(encoding: String.Encoding) throws -> String {
        guard let str = String(data: data, encoding: encoding) else {
            throw SwiftyRSAError(message: "Couldn't convert data to string representation")
        }
        return str
    }
    
    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - key: Public key to encrypt the clear message with
    ///   - padding: Padding to use during the encryption
    /// - Returns: Encrypted message
    /// - Throws: SwiftyRSAError
    public func encrypted(with key: PublicKey, padding: Padding) throws -> EncryptedMessage {
        
        let blockSize = SecKeyGetBlockSize(key.reference)
        let maxChunkSize = (padding == []) ? blockSize : blockSize - 11
        
        var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
        
        var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < decryptedDataAsArray.count {
            
            let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
            let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
            
            var encryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var encryptedDataLength = blockSize
            
            let status = SecKeyEncrypt(key.reference, padding, chunkData, chunkData.count, &encryptedDataBuffer, &encryptedDataLength)
            
            guard status == noErr else {
                throw SwiftyRSAError(message: "Couldn't encrypt chunk at index \(idx)")
            }
            
            encryptedDataBytes += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        let encryptedData = Data(bytes: UnsafePointer<UInt8>(encryptedDataBytes), count: encryptedDataBytes.count)
        return EncryptedMessage(data: encryptedData)
    }
    
    /// Signs a clear message using a private key.
    /// The clear message will first be hashed using the specified digest type, then signed
    /// using the provided private key.
    ///
    /// - Parameters:
    ///   - key: Private key to sign the clear message with
    ///   - digestType: Digest
    /// - Returns: Signature of the clear message after signing it with the specified digest type.
    /// - Throws: SwiftyRSAError
    public func signed(with key: PrivateKey, digestType: Signature.DigestType) throws -> Signature {
        
        let digest = self.digest(digestType: digestType)
        let blockSize = SecKeyGetBlockSize(key.reference)
        let maxChunkSize = blockSize - 11
        
        guard digest.count <= maxChunkSize else {
            throw SwiftyRSAError(message: "data length exceeds \(maxChunkSize)")
        }
        
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: blockSize)
        var signatureDataLength = blockSize
        
        let status = SecKeyRawSign(key.reference, digestType.padding, digestBytes, digestBytes.count, &signatureBytes, &signatureDataLength)
        
        guard status == noErr else {
            throw SwiftyRSAError(message: "Couldn't sign data \(status)")
        }
        
        let signatureData = Data(bytes: UnsafePointer<UInt8>(signatureBytes), count: signatureBytes.count)
        return Signature(data: signatureData)
    }
    
    /// Verifies the signature of a clear message.
    ///
    /// - Parameters:
    ///   - key: Public key to verify the signature with
    ///   - signature: Signature to verify
    ///   - digestType: Digest type used for the signature
    /// - Returns: Result of the verification
    /// - Throws: SwiftyRSAError
    public func verify(with key: PublicKey, signature: Signature, digestType: Signature.DigestType) throws -> VerificationResult {
        
        let digest = self.digest(digestType: digestType)
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.data.count)
        (signature.data as NSData).getBytes(&signatureBytes, length: signature.data.count)
        
        let status = SecKeyRawVerify(key.reference, digestType.padding, digestBytes, digestBytes.count, signatureBytes, signatureBytes.count)
        
        if status == errSecSuccess {
            return VerificationResult(isSuccessful: true)
        } else if status == -9809 {
            return VerificationResult(isSuccessful: false)
        } else {
            throw SwiftyRSAError(message: "Couldn't verify signature - \(status)")
        }
    }
    
    func digest(digestType: Signature.DigestType) -> Data {
        
        let digest: Data
        
        switch digestType {
        case .sha1:
            digest = (data as NSData).swiftyRSASHA1()
        case .sha224:
            digest = (data as NSData).swiftyRSASHA224()
        case .sha256:
            digest = (data as NSData).swiftyRSASHA256()
        case .sha384:
            digest = (data as NSData).swiftyRSASHA384()
        case .sha512:
            digest = (data as NSData).swiftyRSASHA512()
        }
        
        return digest
    }
}
