//
//  Asn1ParserTests.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/9/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import XCTest

@testable import SwiftyRSA

class Asn1ParserTests: XCTestCase {
    func test() {
        let data = TestUtils.derKeyData(name: "swiftyrsa-public")
        do {
            let node = try Asn1Parser.parse(data: data)
            
        } catch {
            print(error)
        }
        
    }
}
