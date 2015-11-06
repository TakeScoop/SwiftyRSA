//
//  SwiftyRSA.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 7/2/15.
//  Copyright (c) 2015 Scoop Technologies, Inc. All rights reserved.
//

import Foundation

public class SwiftyRSAError: NSError {
    init(message: String) {
        super.init(domain: "com.takescoop.SwiftyRSA", code: 500, userInfo: [
            NSLocalizedDescriptionKey: message
        ])
    }

    @available(*, unavailable)
    required public init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}

public class SwiftyRSA {
    
    private var keyTags: [NSData] = []
    private static let defaultPadding: SecPadding = .PKCS1
    
    // MARK: - Public Shorthands
    
    public class func encryptString(str: String, publicKeyPEM: String, padding: SecPadding = defaultPadding) throws -> String {
        let rsa = SwiftyRSA()
        let key = try rsa.publicKeyFromPEMString(publicKeyPEM)
        return try rsa.encryptString(str, publicKey: key, padding: padding)
    }
    
    public class func encryptString(str: String, publicKeyDER: NSData, padding: SecPadding = defaultPadding) throws -> String {
        let rsa = SwiftyRSA()
        let key = try rsa.publicKeyFromDERData(publicKeyDER)
        return try rsa.encryptString(str, publicKey: key, padding: padding)
    }
    
    public class func decryptString(str: String, privateKeyPEM: String, padding: SecPadding = defaultPadding) throws -> String {
        let rsa = SwiftyRSA()
        let key = try rsa.privateKeyFromPEMString(privateKeyPEM)
        return try rsa.decryptString(str, privateKey: key, padding: padding)
    }
    
    // MARK: - Public Advanced Methods
    
    public init() {}
    
    public func publicKeyFromDERData(keyData: NSData) throws -> SecKeyRef {
        return try addKey(keyData, isPublic: true)
    }
    
    public func publicKeyFromPEMString(key: String) throws -> SecKeyRef {
        let data = try dataFromPEMKey(key)
        return try addKey(data, isPublic: true)
    }
    
    public func privateKeyFromPEMString(key: String) throws -> SecKeyRef {
        let data = try dataFromPEMKey(key)
        return try addKey(data, isPublic: false)
    }
    
    public func encryptString(str: String, publicKey: SecKeyRef, padding: SecPadding = defaultPadding) throws -> String {
        let blockSize = SecKeyGetBlockSize(publicKey)
        let plainTextData = [UInt8](str.utf8)
        let plainTextDataLength = Int(str.characters.count)
        var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var encryptedDataLength = blockSize
        
        let status = SecKeyEncrypt(publicKey, padding, plainTextData, plainTextDataLength, &encryptedData, &encryptedDataLength)
        if status != noErr {
            throw SwiftyRSAError(message: "Couldn't encrypt provided string. OSStatus: \(status)")
        }
        
        let data = NSData(bytes: encryptedData, length: encryptedDataLength)
        return data.base64EncodedStringWithOptions([])
    }
    
    public func decryptString(str: String, privateKey: SecKeyRef, padding: SecPadding = defaultPadding) throws -> String {
        
        guard let data = NSData(base64EncodedString: str, options: []) else {
            throw SwiftyRSAError(message: "Couldn't decode base 64 encoded string")
        }
        
        let blockSize = SecKeyGetBlockSize(privateKey)
        
        var encryptedData = [UInt8](count: blockSize, repeatedValue: 0)
        data.getBytes(&encryptedData, length: blockSize)
        
        var decryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var decryptedDataLength = blockSize
        
        let status = SecKeyDecrypt(privateKey, padding, encryptedData, blockSize, &decryptedData, &decryptedDataLength)
        if status != noErr {
            throw SwiftyRSAError(message: "Couldn't decrypt provided string. OSStatus: \(status)")
        }
        
        let decryptedNSData = NSData(bytes: decryptedData, length: decryptedDataLength)
        guard let decryptedString = NSString(data: decryptedNSData, encoding: NSUTF8StringEncoding) else {
            throw SwiftyRSAError(message: "Couldn't convert decrypted data to UTF8 string")
        }
        
        return decryptedString as String
    }
    
    // MARK: - Private
    
    private func addKey(keyData: NSData, isPublic: Bool) throws -> SecKeyRef {
        
        var keyData = keyData
        
        // Strip key header if necessary
        if isPublic {
            try keyData = stripPublicKeyHeader(keyData)
        }
        
        let tag = NSUUID().UUIDString
        let tagData = NSData(bytes: tag, length: tag.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        removeKeyWithTagData(tagData)
        
        // Add persistent version of the key to system keychain
        let persistKey = UnsafeMutablePointer<AnyObject?>()
        let keyClass   = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        
        // Add persistent version of the key to system keychain
        let keyDict = NSMutableDictionary()
        keyDict.setObject(kSecClassKey,         forKey: kSecClass as! NSCopying)
        keyDict.setObject(tagData,              forKey: kSecAttrApplicationTag as! NSCopying)
        keyDict.setObject(kSecAttrKeyTypeRSA,   forKey: kSecAttrKeyType as! NSCopying)
        keyDict.setObject(keyData,              forKey: kSecValueData as! NSCopying)
        keyDict.setObject(keyClass,             forKey: kSecAttrKeyClass as! NSCopying)
        keyDict.setObject(NSNumber(bool: true), forKey: kSecReturnPersistentRef as! NSCopying)
        keyDict.setObject(kSecAttrAccessibleWhenUnlocked, forKey: kSecAttrAccessible as! NSCopying)
        
        var secStatus = SecItemAdd(keyDict as CFDictionary, persistKey)
        if secStatus != noErr && secStatus != errSecDuplicateItem {
            throw SwiftyRSAError(message: "Provided key couldn't be added to the keychain")
        }
        
        keyTags.append(tagData)
        
        // Now fetch the SecKeyRef version of the key
        var keyRef: AnyObject? = nil
        keyDict.removeObjectForKey(kSecValueData)
        keyDict.removeObjectForKey(kSecReturnPersistentRef)
        keyDict.setObject(NSNumber(bool: true), forKey: kSecReturnRef as! NSCopying)
        keyDict.setObject(kSecAttrKeyTypeRSA,   forKey: kSecAttrKeyType as! NSCopying)
        secStatus = SecItemCopyMatching(keyDict as CFDictionaryRef, &keyRef)
        
        guard let unwrappedKeyRef = keyRef else {
            throw SwiftyRSAError(message: "Couldn't get key reference from the keychain")
        }
        
        return unwrappedKeyRef as! SecKeyRef
    }
    
    private func dataFromPEMKey(key: String) throws -> NSData {
        let rawLines = key.componentsSeparatedByString("\n")
        var lines = [String]()
        
        for line in rawLines {
            if line == "-----BEGIN RSA PRIVATE KEY-----" ||
                line == "-----END RSA PRIVATE KEY-----"   ||
                line == "-----BEGIN PUBLIC KEY-----" ||
                line == "-----END PUBLIC KEY-----"   ||
                line == "" {
                    continue
            }
            lines.append(line)
        }
        
        if lines.count == 0 {
            throw SwiftyRSAError(message: "Couldn't get data from PEM key: no data available after stripping headers")
        }
        
        // Decode base64 key
        let base64EncodedKey = lines.joinWithSeparator("")
        let keyData = NSData(base64EncodedString: base64EncodedKey, options: .IgnoreUnknownCharacters)
        
        guard let unwrappedKeyData = keyData where unwrappedKeyData.length != 0 else {
            throw SwiftyRSAError(message: "Couldn't decode PEM key data (base64)")
        }
        
        return unwrappedKeyData
    }
    
    private func stripPublicKeyHeader(keyData: NSData) throws -> NSData {
        let count = keyData.length / sizeof(CUnsignedChar)
        var byteArray = [CUnsignedChar](count: count, repeatedValue: 0)
        keyData.getBytes(&byteArray, length: keyData.length)
        
        var index = 0
        if byteArray[index++] != 0x30 {
            throw SwiftyRSAError(message: "Invalid byte at index 0 (\(byteArray[0])) for public key header")
        }
        
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        }
        else {
            index++
        }
        
        let seqiod: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, 0x05, 0x00]
        byteArray.replaceRange(Range<Int>(start: index, end: index + seqiod.count), with: seqiod)
        
        index += 15
        
        if byteArray[index++] != 0x03 {
            throw SwiftyRSAError(message: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
        }
        
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        }
        else {
            index++
        }
        
        if byteArray[index++] != 0 {
            throw SwiftyRSAError(message: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
        }
        
        let test = [CUnsignedChar](byteArray[index...keyData.length - 1])
        
        let data = NSData(bytes: test, length: keyData.length - index)
        
        return data
    }
    
    private func removeKeyWithTagData(tagData: NSData) {
        let publicKey = NSMutableDictionary()
        publicKey.setObject(kSecClassKey,       forKey: kSecClass as! NSCopying)
        publicKey.setObject(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType as! NSCopying)
        publicKey.setObject(tagData,            forKey: kSecAttrApplicationTag as! NSCopying)
        SecItemDelete(publicKey as CFDictionaryRef)
    }
    
    deinit {
        for tagData in keyTags {
            removeKeyWithTagData(tagData)
        }
    }
}
