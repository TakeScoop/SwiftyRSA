//
//  EncryptedMessage.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/18/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

public class EncryptedMessage: Message {
    
    /// Data of the message
    public let data: Data
    
    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    public required init(data: Data) {
        self.data = data
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
                throw SwiftyRSAError.chunkDecryptFailed(index: idx)
            }
            
            decryptedDataBytes += [UInt8](decryptedDataBuffer[0..<decryptedDataLength])
            
            idx += blockSize
        }
        
        let decryptedData = Data(bytes: decryptedDataBytes, count: decryptedDataBytes.count)
        return ClearMessage(data: decryptedData)
    }
}
