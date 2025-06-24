// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "SwiftyRSA",
    products: [
        .library(
            name: "SwiftyRSASDK",
            targets: ["SwiftyRSASDK"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "SwiftyRSASDK",
            dependencies: [],
            path: "Source")
    ]
)
