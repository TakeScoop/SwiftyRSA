// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let rocketIfNeeded: [Package.Dependency]

rocketIfNeeded = []

let package = Package(
    name: "SwiftyRSA",
    platforms: [.iOS(.v11)],
    products: [
        .library(
            name: "SwiftyRSA",
            targets: ["SwiftyRSA"]),
    ],
    dependencies: [] + rocketIfNeeded,
    targets: [
        .target(
            name: "SwiftyRSA",
            exclude: ["Supporting Files/Info.plist",
                      "Supporting Files/Info-tvOS.plist",
                      "Supporting Files/NSData+SHA.h",
                      "Supporting Files/NSData+SHA.m",
                      "Supporting Files/SwiftyRSA.h"
                     ]),
        .testTarget( // dev
            name: "SwiftyRSATests", // dev
            dependencies: ["SwiftyRSA"],
            path: "Tests/SwiftyRSATests", // dev
            exclude: ["Supporting Files"]), // dev
    ], // dev
    swiftLanguageVersions: [.v5]
)
