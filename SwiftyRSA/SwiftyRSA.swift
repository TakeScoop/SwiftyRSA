//
//  SwiftyRSA.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 7/2/15.
//  Copyright (c) 2015 Scoop Technologies, Inc. All rights reserved.
//

import Foundation
import Security

public typealias Padding = SecPadding

struct SwiftyRSAError: Error {
    let message: String
    
    init(message: String) {
        self.message = message
    }
}

extension CFString: Hashable {
    public var hashValue: Int {
        return (self as String).hashValue
    }
    
    static public func == (lhs: CFString, rhs: CFString) -> Bool {
        return lhs as String == rhs as String
    }
}

enum SwiftyRSA {
    
    static func base64String(pemEncoded pemString: String) throws -> String {
        let lines = pemString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        
        guard lines.count != 0 else {
            throw SwiftyRSAError(message: "Couldn't get data from PEM key: no data available after stripping headers")
        }
        
        return lines.joined(separator: "")
    }
    
    static func isValidKeyReference(_ reference: SecKey, forClass requiredClass: CFString) -> Bool {
        
        guard #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) else {
            return true
        }
        
        let attributes = SecKeyCopyAttributes(reference) as? [CFString: Any]
        guard let keyType = attributes?[kSecAttrKeyType] as? String, let keyClass = attributes?[kSecAttrKeyClass] as? String else {
            return false
        }
        
        let isRSA = keyType == (kSecAttrKeyTypeRSA as String)
        let isValidClass = keyClass == (requiredClass as String)
        return isRSA && isValidClass
    }
    
    static func format(keyData: Data, withPemType pemType: String) -> String {
        
        func split(_ str: String, byChunksOfLength length: Int) -> [String] {
            return stride(from: 0, to: str.characters.count, by: length).map { index -> String in
                let startIndex = str.index(str.startIndex, offsetBy: index)
                let endIndex = str.index(startIndex, offsetBy: length, limitedBy: str.endIndex) ?? str.endIndex
                return str[startIndex..<endIndex]
            }
        }
        
        // Line length is typically 64 characters, except the last line.
        // See https://tools.ietf.org/html/rfc7468#page-6 (64base64char)
        // See https://tools.ietf.org/html/rfc7468#page-11 (example)
        let chunks = split(keyData.base64EncodedString(), byChunksOfLength: 64)
        
        let pem = [
            "-----BEGIN \(pemType)-----",
            chunks.joined(separator: "\n"),
            "-----END \(pemType)-----"
        ]
        
        return pem.joined(separator: "\n")
    }
    
    static func data(forKeyReference reference: SecKey) throws -> Data {
        
        // On iOS+, we can use `SecKeyCopyExternalRepresentation` directly
        if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
            
            let data = SecKeyCopyExternalRepresentation(reference, nil)
            guard let unwrappedData = data as Data? else {
                throw SwiftyRSAError(message: "Couldn't retrieve key data from the keychain")
            }
            return unwrappedData
        
        // On iOS 8/9, we need to add the key again to the keychain with a temporary tag, grab the data,
        // and delete the key again.
        } else {
            
            let temporaryTag = UUID().uuidString
            let addParams: [CFString: Any] = [
                kSecValueRef: reference,
                kSecReturnData: true,
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: temporaryTag
            ]
            
            var data: AnyObject?
            _ = SecItemAdd(addParams as CFDictionary, &data)
            guard let unwrappedData = data as? Data else {
                throw SwiftyRSAError(message: "Couldn't retrieve key data from the keychain")
            }
            
            let deleteParams: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: temporaryTag
            ]
            
            _ = SecItemDelete(deleteParams as CFDictionary)
            
            return unwrappedData
        }
    }
    
    static func addKey(_ keyData: Data, isPublic: Bool, tag: String) throws ->  SecKey {
        
        var keyData = keyData
        
        guard let tagData = tag.data(using: .utf8) else {
            throw SwiftyRSAError(message: "Couldn't create tag data for key")
        }
        
        let keyClass = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        
        // On iOS 10+, we can use SecKeyCreateWithData without going through the keychain
        if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
            
            let sizeInBits = keyData.count * 8
            let keyDict: [CFString: Any] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: keyClass,
                kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
                kSecReturnPersistentRef: true
            ]
            
            guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, nil) else {
                throw SwiftyRSAError(message: "Couldn't create key reference from key data")
            }
            return key
            
        // On iOS 9 and earlier, add a persistent version of the key to the system keychain
        } else {
            
            let persistKey = UnsafeMutablePointer<AnyObject?>(mutating: nil)
            
            let keyAddDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: tagData,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecValueData: keyData,
                kSecAttrKeyClass: keyClass,
                kSecReturnPersistentRef: true,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked
            ]
            
            let secStatus = SecItemAdd(keyAddDict as CFDictionary, persistKey)
            guard secStatus == errSecSuccess || secStatus == errSecDuplicateItem else {
                throw SwiftyRSAError(message: "Provided key couldn't be added to the keychain")
            }
            
            let keyCopyDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: tagData,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: keyClass,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
                kSecReturnRef: true,
            ]
            
            // Now fetch the SecKeyRef version of the key
            var keyRef: AnyObject? = nil
            _ = SecItemCopyMatching(keyCopyDict as CFDictionary, &keyRef)
            
            guard let unwrappedKeyRef = keyRef else {
                throw SwiftyRSAError(message: "Couldn't get key reference from the keychain")
            }
            
            return unwrappedKeyRef as! SecKey // swiftlint:disable:this force_cast
        }
    }
    
    /**
     This method strips the x509 header from a provided ASN.1 DER public key.
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
    static func stripPublicKeyHeader(keyData: Data) throws -> Data {
        let count = keyData.count / MemoryLayout<CUnsignedChar>.size
        
        guard count > 0 else {
            throw SwiftyRSAError(message: "Provided public key is empty")
        }
        
        var byteArray = [UInt8](repeating: 0, count: count)
        (keyData as NSData).getBytes(&byteArray, length: keyData.count)
        
        var index = 0
        guard byteArray[index] == 0x30 else {
            throw SwiftyRSAError(message: "Provided key doesn't have a valid ASN.1 structure (first byte should be 0x30 == SEQUENCE)")
        }
        
        index += 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
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
        if byteArray[index] != 0x03 {
            throw SwiftyRSAError(message: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
        }
        
        index += 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
        }
        
        guard byteArray[index] == 0 else {
            throw SwiftyRSAError(message: "Invalid byte at index \(index - 1) (\(byteArray[index - 1])) for public key header")
        }
        
        index += 1
        
        let strippedKeyBytes = [UInt8](byteArray[index...keyData.count - 1])
        let data = Data(bytes: UnsafePointer<UInt8>(strippedKeyBytes), count: keyData.count - index)
        
        return data
    }
    
    static func removeKey(tag: String) {
        
        guard let tagData = tag.data(using: .utf8) else {
            return
        }
        
        let keyRemoveDict: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag: tagData,
        ]
        
        SecItemDelete(keyRemoveDict as CFDictionary)
    }
}
