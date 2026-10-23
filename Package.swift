// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftyRSA",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_15),
        .tvOS(.v12),
        .watchOS(.v5),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "SwiftyRSA",
            targets: ["SwiftyRSA"]
        )
    ],
    targets: [
        .target(
            name: "SwiftyRSA",
            path: "Source",
            exclude: [
                "Info.plist",
                "Info-tvOS.plist",
                "SwiftyRSA+ObjC.swift"
            ],
            resources: [
                .copy("PrivacyInfo.xcprivacy")
            ]
        ),
        .testTarget(
            name: "SwiftyRSATests",
            dependencies: ["SwiftyRSA"],
            path: "Tests",
            exclude: [
                "Info.plist",
                "ObjCTests.m",
                "keys/multiple-keys-testcase.sh"
            ],
            resources: [
                // Flatten into the test bundle root so pemNamed/derNamed resolve.
                .copy("keys/multiple-keys-testcase.pem"),
                .copy("keys/swiftyrsa-private-header-octetstring.pem"),
                .copy("keys/swiftyrsa-private-headerless.pem"),
                .copy("keys/swiftyrsa-private.der"),
                .copy("keys/swiftyrsa-private.pem"),
                .copy("keys/swiftyrsa-public-base64-X509-format.txt"),
                .copy("keys/swiftyrsa-public-base64-newlines.txt"),
                .copy("keys/swiftyrsa-public-base64.txt"),
                .copy("keys/swiftyrsa-public-headerless.pem"),
                .copy("keys/swiftyrsa-public.der"),
                .copy("keys/swiftyrsa-public.pem")
            ]
        )
    ]
)
