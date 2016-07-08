//
//  TestUtils.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 4/1/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

@objc public class TestUtils: NSObject {
    static public func pemKeyString(name: String) -> String {
        let bundle = Bundle(for: TestUtils.self)
        let pubPath = bundle.pathForResource(name, ofType: "pem")!
        return (try! NSString(contentsOfFile: pubPath, encoding: String.Encoding.utf8.rawValue)) as String
    }
    
    static public func derKeyData(name: String) -> Data {
        let bundle = Bundle(for: TestUtils.self)
        let pubPath  = bundle.pathForResource(name, ofType: "der")!
        return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
    }
}
