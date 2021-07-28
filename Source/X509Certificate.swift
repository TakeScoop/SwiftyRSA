//
//  X509Certificate.swift
//  SwiftyRSA
//
//  Created by Stchepinsky Nathan on 24/06/2021.
//  Copyright © 2021 Scoop. All rights reserved.
//

import Foundation


///
/// Encoding/Decoding lengths as octets
///
private extension NSInteger {
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)];
        }
        
        // Long form
        let i = Int(log2(Double(self)) / 8 + 1)
        var len = self
        var result: [CUnsignedChar] = [CUnsignedChar(i + 0x80)]
        
        for _ in 0..<i {
            result.insert(CUnsignedChar(len & 0xFF), at: 1)
            len = len >> 8
        }
        
        return result
    }
    
    init?(octetBytes: [CUnsignedChar], startIdx: inout NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] as UInt8 - 128)
            
            if octets > octetBytes.count - startIdx {
                self.init(0)
                return nil
            }
            
            var result = UInt64(0)
            
            for j in 1...octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIdx + j])
            }
            
            startIdx += 1 + octets
            self.init(result)
        }
    }
}



public extension Data{
    // This code source come from Heimdall project https://github.com/henrinormak/Heimdall published under MIT Licence
    
    /// This method prepend the X509 header to a given public key
    func prependx509Header() -> Data {
        let result = NSMutableData()
                
        let encodingLength: Int = (self.count + 1).encodedOctets().count
        let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
                
        var builder: [CUnsignedChar] = []
                
        // ASN.1 SEQUENCE
        builder.append(0x30)
                
        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.count
        let encodedSize = size.encodedOctets()
        builder.append(contentsOf: encodedSize)
        result.append(builder, length: builder.count)
        result.append(OID, length: OID.count)
        builder.removeAll(keepingCapacity: false)
                
        builder.append(0x03)
        builder.append(contentsOf: (self.count + 1).encodedOctets())
        builder.append(0x00)
        result.append(builder, length: builder.count)
                
        // Actual key bytes
        result.append(self)
                
        return result as Data
    }
    
    func hasX509Header() throws -> Bool{
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: self)
        } catch {
            throw SwiftyRSAError.asn1ParsingFailed
        }
        
        
        // Ensure the raw data is an ASN1 sequence
        guard case .sequence(let nodes) = node else {
            return false
        }
        
        // Must contain 2 elements, a sequence and a bit string
        if nodes.count != 2 {
            return false
        }
        
        // Ensure the first node is an ASN1 sequence
        guard case .sequence(let firstNode) =  nodes[0] else {
            return false
        }
        
        // Must contain 2 elements, an object id and NULL
        if firstNode.count != 2 {
            return false
        }
        
        guard case .objectIdentifier(_) = firstNode[0] else {
            return false
        }
        
        guard case .null = firstNode[1] else {
            return false
        }
        
        // The 2sd child has to be a bit string containing a sequence of 2 int
        
        
        let last = nodes[1]
        if case .bitString(let secondChildSequence) = last {
            return try secondChildSequence.isAnHeaderlessKey()
        } else {
            return false
        }
    }
    
    func isAnHeaderlessKey() throws -> Bool{
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: self)
        } catch {
            throw SwiftyRSAError.asn1ParsingFailed
        }
        
        // Ensure the raw data is an ASN1 sequence
        guard case .sequence(let nodes) = node else {
            return false
        }
        
        // Detect whether the sequence only has integers, in which case it's a headerless key
        let onlyHasIntegers = nodes.filter { node -> Bool in
            if case .integer = node {
                return false
            }
            return true
        }.isEmpty
        
        // Headerless key
        return onlyHasIntegers
    }
}
