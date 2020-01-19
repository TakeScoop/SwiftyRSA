//
//  Data+SHA.swift
//  SwiftyRSA
//
//  Created by Sameh sayed on 1/19/20.
//  Copyright © 2020 Sameh sayed. All rights reserved.
//

import Foundation
import CommonCrypto

extension NSData{

    func swiftyRSASHA512()->Data{
        let outputLenght = CC_SHA512_DIGEST_LENGTH
        let output = UnsafeMutablePointer<UInt8>(bitPattern: Int(outputLenght))

        CC_SHA512(self.bytes, CC_LONG(self.length), output)
        return Data(bytes: output!, count: Int(outputLenght))
    }


    func swiftyRSASHA384()->Data{
        let outputLenght = CC_SHA384_DIGEST_LENGTH
        let output = UnsafeMutablePointer<UInt8>(bitPattern: Int(outputLenght))

        CC_SHA384(self.bytes, CC_LONG(self.length), output)
        return Data(bytes: output!, count: Int(outputLenght))
    }



    func swiftyRSASHA256()->Data{
        let outputLenght = CC_SHA256_DIGEST_LENGTH
        let output = UnsafeMutablePointer<UInt8>(bitPattern: Int(outputLenght))

        CC_SHA256(self.bytes, CC_LONG(self.length), output)
        return Data(bytes: output!, count: Int(outputLenght))
    }


    func swiftyRSASHA224()->Data{
        let outputLenght = CC_SHA224_DIGEST_LENGTH
        let output = UnsafeMutablePointer<UInt8>(bitPattern: Int(outputLenght))

        CC_SHA224(self.bytes, CC_LONG(self.length), output)
        return Data(bytes: output!, count: Int(outputLenght))
    }


    func swiftyRSASHA1()->Data {
        let outputLenght = CC_SHA1_DIGEST_LENGTH
        let output = UnsafeMutablePointer<UInt8>(bitPattern: Int(outputLenght))
        CC_SHA1(self.bytes, CC_LONG(self.length), output)
        return Data(bytes: output!, count: Int(outputLenght))
    }


    

}
