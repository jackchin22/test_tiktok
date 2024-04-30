//
//  Person.swift
//  test_tiktok
//
//  Created by chenxi on 2024/3/19.
//

import Foundation
import UIKit

public class Person:NSObject{
    @objc public var name:String=""
    
    @objc public func test(){
         
        
        let cQueue = DispatchQueue(label: "cQueue", attributes: [.concurrent])
        print(1)
        cQueue.async {
            print("\(2)：\(Thread.current)")
            print("\(2)：\(Thread.current)")
            print("\(2)：\(Thread.current)")
        }
        print(3)
        cQueue.async {
            print("\(4)：\(Thread.current)")
            print("\(4)：\(Thread.current)")
            print("\(4)：\(Thread.current)")
        }
        print(5)
        
    }
    @objc public static func test1(){}
}
