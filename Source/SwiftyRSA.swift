//
//  SwiftyRSA.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 7/2/15.
//  Contributions by Stchepinsky Nathan on 24/06/2021
//  Copyright (c) 2015 Scoop Technologies, Inc. All rights reserved.
//

import Foundation
import Security

public typealias Padding = SecPadding

public enum SwiftyRSA {
    
    static func base64String(pemEncoded pemString: String) throws -> String {
        let lines = pemString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        
        guard lines.count != 0 else {
            throw SwiftyRSAError.pemDoesNotContainKey
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
            return stride(from: 0, to: str.count, by: length).map { index -> String in
                let startIndex = str.index(str.startIndex, offsetBy: index)
                let endIndex = str.index(startIndex, offsetBy: length, limitedBy: str.endIndex) ?? str.endIndex
                return String(str[startIndex..<endIndex])
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
            
            var error: Unmanaged<CFError>?
            let data = SecKeyCopyExternalRepresentation(reference, &error)
            guard let unwrappedData = data as Data? else {
                throw SwiftyRSAError.keyRepresentationFailed(error: error?.takeRetainedValue())
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
            let addStatus = SecItemAdd(addParams as CFDictionary, &data)
            guard let unwrappedData = data as? Data else {
                throw SwiftyRSAError.keyAddFailed(status: addStatus)
            }
            
            let deleteParams: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: temporaryTag
            ]
            
            _ = SecItemDelete(deleteParams as CFDictionary)
            
            return unwrappedData
        }
    }
    
    /// Will generate a new private and public key
    ///
    /// - Parameters:
    ///   - size: Indicates the total number of bits in this cryptographic key
    /// - Returns: A touple of a private and public key
    /// - Throws: Throws and error if the tag cant be parsed or if keygeneration fails
    @available(iOS 10.0, watchOS 3.0, tvOS 10.0, *)
    public static func generateRSAKeyPair(sizeInBits size: Int) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
        return try generateRSAKeyPair(sizeInBits: size, applyUnitTestWorkaround: false)
    }
    
    @available(iOS 10.0, watchOS 3.0, tvOS 10.0, *)
    static func generateRSAKeyPair(sizeInBits size: Int, applyUnitTestWorkaround: Bool = false) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
      
        guard let tagData = UUID().uuidString.data(using: .utf8) else {
            throw SwiftyRSAError.stringToDataConversionFailed
        }
        
        // @hack Don't store permanently when running unit tests, otherwise we'll get a key creation error (NSOSStatusErrorDomain -50)
        // @see http://www.openradar.me/36809637
        // @see https://stackoverflow.com/q/48414685/646960
        let isPermanent = applyUnitTestWorkaround ? false : true
        
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: isPermanent,
                kSecAttrApplicationTag: tagData
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let pubKey = SecKeyCopyPublicKey(privKey) else {
            throw SwiftyRSAError.keyGenerationFailed(error: error?.takeRetainedValue())
        }
        let privateKey = try PrivateKey(reference: privKey)
        let publicKey = try PublicKey(reference: pubKey)
        
        return (privateKey: privateKey, publicKey: publicKey)
    }
    
    static func addKey(_ keyData: Data, isPublic: Bool, tag: String) throws ->  SecKey {
        
        let keyData = keyData
        
        guard let tagData = tag.data(using: .utf8) else {
            throw SwiftyRSAError.tagEncodingFailed
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
            
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
                throw SwiftyRSAError.keyCreateFailed(error: error?.takeRetainedValue())
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
                kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock
            ]
            
            let addStatus = SecItemAdd(keyAddDict as CFDictionary, persistKey)
            guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
                throw SwiftyRSAError.keyAddFailed(status: addStatus)
            }
            
            let keyCopyDict: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: tagData,
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: keyClass,
                kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
                kSecReturnRef: true,
            ]
            
            // Now fetch the SecKeyRef version of the key
            var keyRef: AnyObject?
            let copyStatus = SecItemCopyMatching(keyCopyDict as CFDictionary, &keyRef)
            
            guard let unwrappedKeyRef = keyRef else {
                throw SwiftyRSAError.keyCopyFailed(status: copyStatus)
            }
            
            return unwrappedKeyRef as! SecKey // swiftlint:disable:this force_cast
        }
    }
    
    /**
     This method strips the x509 header from a provided ASN.1 DER key.
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
    static func stripKeyHeader(keyData: Data) throws -> Data {
        
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: keyData)
        } catch {
            throw SwiftyRSAError.asn1ParsingFailed
        }
        
        // Ensure the raw data is an ASN1 sequence
        guard case .sequence(let nodes) = node else {
            throw SwiftyRSAError.invalidAsn1RootNode
        }
        
        // Detect whether the sequence only has integers, in which case it's a headerless key
        let onlyHasIntegers = nodes.filter { node -> Bool in
            if case .integer = node {
                return false
            }
            return true
        }.isEmpty
        
        // Headerless key
        if onlyHasIntegers {
            return keyData
        }
        
        // If last element of the sequence is a bit string, return its data
        if let last = nodes.last, case .bitString(let data) = last {
            return data
        }
        
        // If last element of the sequence is an octet string, return its data
        if let last = nodes.last, case .octetString(let data) = last {
            return data
        }
        
        // Unable to extract bit/octet string or raw integer sequence
        throw SwiftyRSAError.invalidAsn1Structure
    }
    
    /**
        This method prepend the x509 header to the given PublicKey data.
        If the key already contain a x509 header, the given data is returned as is.
            It letterally does the opposite of the previous method :
            From a given headerless key :
                    SEQUENCE
                        INTEGER (1024 or 2048 bit) -- modulo
                        INTEGER -- public exponent
            the key is returned following the X509 header :
                    SEQUENCE
                        SEQUENCE
                        OBJECT IDENTIFIER 1.2.840.113549.1.1.1
                        NULL
                        BIT STRING
                        SEQUENCE
                        INTEGER (1024 or 2048 bit) -- modulo
                        INTEGER -- public exponent
     */
    
    static func prependX509KeyHeader(keyData : Data) throws ->  Data{
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: keyData)
        } catch {
            throw SwiftyRSAError.asn1ParsingFailed
        }
        
        // Ensure the raw data is an ASN1 sequence
        guard case .sequence(let nodes) = node else {
            throw SwiftyRSAError.invalidAsn1RootNode
        }
        
        let onlyHasIntegers = nodes.filter { node -> Bool in
            if case .integer = node {
                return false
            }
            return true
        }.isEmpty
        
        // The key already contains an header
        if !onlyHasIntegers {
            return keyData
        }
        
        let x509certificate : Data = keyData.prependx509Header()
        return x509certificate
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

#if !swift(>=4.1)
extension Array {
    func compactMap<ElementOfResult>(_ transform: (Element) throws -> ElementOfResult?) rethrows -> [ElementOfResult] {
        return try self.flatMap(transform)
    }
}
#endif

#if !swift(>=4.0)
extension NSTextCheckingResult {
    func range(at idx: Int) -> NSRange {
        return self.rangeAt(1)
    }
}
#endif
