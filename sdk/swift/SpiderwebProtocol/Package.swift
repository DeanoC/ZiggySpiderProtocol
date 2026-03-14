// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SpiderwebProtocol",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "SpiderwebProtocol",
            targets: ["SpiderwebProtocol"]
        ),
    ],
    targets: [
        .target(
            name: "SpiderwebProtocol"
        ),
    ]
)
