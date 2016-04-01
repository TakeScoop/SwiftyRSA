//
//  SwiftyRSA.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 7/2/15.
//  Copyright (c) 2015 Scoop Technologies, Inc. All rights reserved.
//

import Foundation
import Security

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

@objc
public class SwiftyRSA: NSObject {
    
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
    
    public override init() {
    	super.init()
    }
    
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
        
        let lines = key.componentsSeparatedByString("\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        
        guard lines.count != 0 else {
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
    
    /**
     This method strips the x509 from a provided ASN.1 DER public key.
     If the key doesn't contain a header, the DER data is returned as is.
     
     Supported formats are:
     
     Headerless:
     SEQUENCE
     	INTEGER (1024 or 2048 bit) -- modulo
     	INTEGER -- public exponent
     
     With x509 header:
     SEQUENCE
     	SEQUENCE
     		OBJECT IDENTIFIER 1.2.840.113549.1.1.1
     		NULL
     	BIT STRING
     		SEQUENCE
     		INTEGER (1024 or 2048 bit) -- modulo
     		INTEGER -- public exponent
     
     Example of headerless key:
     https://lapo.it/asn1js/#3082010A0282010100C1A0DFA367FBC2A5FD6ED5A071E02A4B0617E19C6B5AD11BB61192E78D212F10A7620084A3CED660894134D4E475BAD7786FA1D40878683FD1B7A1AD9C0542B7A666457A270159DAC40CE25B2EAE7CCD807D31AE725CA394F90FBB5C5BA500545B99C545A9FE08EFF00A5F23457633E1DB84ED5E908EF748A90F8DFCCAFF319CB0334705EA012AF15AA090D17A9330159C9AFC9275C610BB9B7C61317876DC7386C723885C100F774C19830F475AD1E9A9925F9CA9A69CE0181A214DF2EB75FD13E6A546B8C8ED699E33A8521242B7E42711066AEC22D25DD45D56F94D3170D6F2C25164D2DACED31C73963BA885ADCB706F40866B8266433ED5161DC50E4B3B0203010001
     
     Example of key with X509 header (notice the additional ASN.1 sequence):
     https://lapo.it/asn1js/#30819F300D06092A864886F70D010101050003818D0030818902818100D0674615A252ED3D75D2A3073A0A8A445F3188FD3BEB8BA8584F7299E391BDEC3427F287327414174997D147DD8CA62647427D73C9DA5504E0A3EED5274A1D50A1237D688486FADB8B82061675ABFA5E55B624095DB8790C6DBCAE83D6A8588C9A6635D7CF257ED1EDE18F04217D37908FD0CBB86B2C58D5F762E6207FF7B92D0203010001
     */
    private func stripPublicKeyHeader(keyData: NSData) throws -> NSData {
        let count = keyData.length / sizeof(CUnsignedChar)
        
        guard count > 0 else {
            throw SwiftyRSAError(message: "Provided public key is empty")
        }
        
        var byteArray = [CUnsignedChar](count: count, repeatedValue: 0)
        keyData.getBytes(&byteArray, length: keyData.length)
        
        var index = 0
        if byteArray[index++] != 0x30 {
            throw SwiftyRSAError(message: "Provided key doesn't have a valid ASN1 structure (first byte should be 0x30 == SEQUENCE)")
        }
        
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        }
        else {
            index++
        }
        
        // If current byte marks an integer (0x02), it means the key doesn't have a X509 header and just
        // contains its modulo & public exponent. In this case, we can just return the provided DER data as is.
        if Int(byteArray[index]) == 0x02 {
            return keyData
        }
        
        // Now that we've excluded the possibility of headerless key, we're looking for a valid X509 header sequence.
        // It should look like this:
        // 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        guard Int(byteArray[index]) == 0x30 else {
            throw SwiftyRSAError(message: "Provided key doesn't have a valid X509 header")
        }
        
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
