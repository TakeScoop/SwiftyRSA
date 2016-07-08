//
//  Data+SHA.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 7/7/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

public extension Data {
    var swiftyRSASHA1: Data {
        return (self as NSData).swiftyRSASHA1()
    }
    
    var swiftyRSASHA224: Data {
        return (self as NSData).swiftyRSASHA224()
    }
    
    var swiftyRSASHA256: Data {
        return (self as NSData).swiftyRSASHA256()
    }
    
    var swiftyRSASHA384: Data {
        return (self as NSData).swiftyRSASHA384()
    }
    
    var swiftyRSASHA512: Data {
        return (self as NSData).swiftyRSASHA512()
    }
}
