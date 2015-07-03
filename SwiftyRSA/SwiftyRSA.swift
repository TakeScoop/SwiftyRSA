//
//  SwiftyRSA.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 7/2/15.
//  Copyright (c) 2015 Scoop. All rights reserved.
//

import Foundation

public class SwiftyRSA {
    
    private var keyTags: [NSData] = []
    
    // MARK: - Public
    
    public init() {}
    
    class func encryptString(str: String, publicKeyPEM: String, padding: SecPadding = SecPadding(kSecPaddingPKCS1)) -> String? {
        let rsa = SwiftyRSA()
        
        let key: SecKeyRef! = rsa.publicKeyFromPEMString(publicKeyPEM)
        if key == nil {
            return nil
        }
        
        return rsa.encryptString(str, publicKey: key, padding: padding)
    }
    
    class func encryptString(str: String, publicKeyDER: NSData, padding: SecPadding = SecPadding(kSecPaddingPKCS1)) -> String? {
        let rsa = SwiftyRSA()
        
        let key: SecKeyRef! = rsa.publicKeyFromDERData(publicKeyDER)
        if key == nil {
            return nil
        }
        
        return rsa.encryptString(str, publicKey: key, padding: padding)
    }
    
    class func decryptString(str: String, privateKeyPEM: String, padding: SecPadding = SecPadding(kSecPaddingPKCS1)) -> String? {
        let rsa = SwiftyRSA()
        
        let key: SecKeyRef! = rsa.privateKeyFromPEMString(privateKeyPEM)
        if key == nil {
            return nil
        }
        
        return rsa.decryptString(str, privateKey: key, padding: padding)
    }
    
    public func publicKeyFromDERData(keyData: NSData) -> SecKeyRef? {
        return addKey(keyData, isPublic: true)
    }
    
    public func publicKeyFromPEMString(key: String) -> SecKeyRef? {
        let data = dataFromPEMKey(key)
        if data == nil {
            return nil
        }
        return addKey(data!, isPublic: true)
    }
    
    public func privateKeyFromPEMString(key: String) -> SecKeyRef? {
        let data = dataFromPEMKey(key)
        if data == nil {
            return nil
        }
        return addKey(data!, isPublic: false)
    }
    
    public func encryptString(str: String, publicKey: SecKeyRef, padding: SecPadding = SecPadding(kSecPaddingPKCS1)) -> String? {
        let blockSize = SecKeyGetBlockSize(publicKey)
        let plainTextData = [UInt8](str.utf8)
        let plainTextDataLength = Int(count(str))
        var encryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var encryptedDataLength = blockSize
        
        let status = SecKeyEncrypt(publicKey, padding, plainTextData, plainTextDataLength, &encryptedData, &encryptedDataLength)
        if status != noErr {
            return nil
        }
        
        let data: NSData! = NSData(bytes: encryptedData, length: encryptedDataLength)
        if data == nil {
            return nil
        }
        
        return data.base64EncodedStringWithOptions(nil)
    }
    
    public func decryptString(str: String, privateKey: SecKeyRef, padding: SecPadding = SecPadding(kSecPaddingPKCS1)) -> String? {
        
        let data: NSData! = NSData(base64EncodedString: str, options: NSDataBase64DecodingOptions(0))
        if data == nil {
            return nil
        }
        
        let blockSize = SecKeyGetBlockSize(privateKey)
        
        var encryptedData = [UInt8](count: blockSize, repeatedValue: 0)
        data.getBytes(&encryptedData, length: blockSize)
        
        var decryptedData = [UInt8](count: Int(blockSize), repeatedValue: 0)
        var decryptedDataLength = blockSize
        
        let result = SecKeyDecrypt(privateKey, padding, encryptedData, blockSize, &decryptedData, &decryptedDataLength)
        
        let decryptedNSData = NSData(bytes: decryptedData, length: decryptedDataLength)
        return NSString(data: decryptedNSData, encoding: NSUTF8StringEncoding) as? String
    }
    
    // MARK: - Private
    
    private func addKey(keyData: NSData, isPublic: Bool) -> SecKeyRef? {
        
        var keyData: NSData! = keyData
        
        // Strip key header if necessary
        if isPublic {
            keyData = stripPublicKeyHeader(keyData)
            if keyData == nil {
                return nil
            }
        }
        
        let tag = NSUUID().UUIDString
        let tagData = NSData(bytes: tag, length: tag.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        removeKeyWithTagData(tagData)
        
        // Add persistent version of the key to system keychain
        let persistKey = UnsafeMutablePointer<Unmanaged<AnyObject>?>()
        let keyClass   = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        
        // Add persistent version of the key to system keychain
        let keyDict = NSMutableDictionary()
        keyDict.setObject(kSecClassKey,            forKey: kSecClass as! NSCopying)
        keyDict.setObject(tagData,                 forKey: kSecAttrApplicationTag as! NSCopying)
        keyDict.setObject(kSecAttrKeyTypeRSA,      forKey: kSecAttrKeyType as! NSCopying)
        keyDict.setObject(keyData,                 forKey: kSecValueData as! NSCopying)
        keyDict.setObject(keyClass,                forKey: kSecAttrKeyClass as! NSCopying)
        keyDict.setObject(NSNumber(bool: true),    forKey: kSecReturnPersistentRef as! NSCopying)
        keyDict.setObject(kSecAttrAccessibleWhenUnlocked, forKey: kSecAttrAccessible as! NSCopying)
        
        var secStatus = SecItemAdd(keyDict as CFDictionaryRef, persistKey)
        if secStatus != noErr && secStatus != errSecDuplicateItem {
            return nil
        }
        
        keyTags.append(tagData)
        
        // Now fetch the SecKeyRef version of the key
        var keyRef: Unmanaged<AnyObject>? = nil
        keyDict.removeObjectForKey(kSecValueData)
        keyDict.removeObjectForKey(kSecReturnPersistentRef)
        keyDict.setObject(NSNumber(bool: true), forKey: kSecReturnRef as! NSCopying)
        keyDict.setObject(kSecAttrKeyTypeRSA,   forKey: kSecAttrKeyType as! NSCopying)
        secStatus = SecItemCopyMatching(keyDict as CFDictionaryRef, &keyRef)
        
        return keyRef != nil ? (keyRef!.takeRetainedValue() as! SecKeyRef) : nil
    }
    
    private func dataFromPEMKey(key: String) -> NSData? {
        var rawLines = key.componentsSeparatedByString("\n")
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
            return nil
        }
        
        // Decode base64 key
        let base64EncodedKey = "".join(lines)
        var keyData: NSData! = NSData(base64EncodedString: base64EncodedKey, options: .IgnoreUnknownCharacters)
        if keyData == nil || keyData!.length == 0 {
            return nil
        }
        
        return keyData
    }
    
    private func stripPublicKeyHeader(keyData: NSData) -> NSData? {
        let count = keyData.length / sizeof(CUnsignedChar)
        var byteArray = [CUnsignedChar](count: count, repeatedValue: 0)
        keyData.getBytes(&byteArray, length: keyData.length)
        
        var index = 0
        if byteArray[index++] != 0x30 {
            return nil
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
            return nil
        }
        
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        }
        else {
            index++
        }
        
        if byteArray[index++] != 0 {
            return nil
        }
        
        let len = keyData.length
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
