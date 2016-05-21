//
//  TestUtils.swift
//  SwiftyRSA
//
//  Created by Loïs Di Qual on 4/1/16.
//  Copyright © 2016 Scoop. All rights reserved.
//

import Foundation

@objc public class TestUtils: NSObject {
    static public func pemKeyString(name name: String) -> String {
        let bundle = NSBundle(forClass: TestUtils.self)
        let pubPath = bundle.pathForResource(name, ofType: "pem")!
        return (try! NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding)) as String
    }
    
    static public func derKeyData(name name: String) -> NSData {
        let bundle = NSBundle(forClass: TestUtils.self)
        let pubPath  = bundle.pathForResource(name, ofType: "der")!
        return NSData(contentsOfFile: pubPath)!
    }
}
