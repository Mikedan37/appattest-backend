// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AppAttestBackend",
    products: [
        .executable(
            name: "AppAttestBackend",
            targets: ["AppAttestBackend"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(path: "../AppAttestDecoder"),
        .package(path: "../AppAttestValidator")
    ],
    targets: [
        .executableTarget(
            name: "AppAttestBackend",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "AppAttestCore", package: "AppAttestDecoder"),
                .product(name: "AppAttestValidator", package: "AppAttestValidator")
            ]
        ),
        .testTarget(
            name: "AppAttestBackendTests",
            dependencies: [
                .target(name: "AppAttestBackend"),
                .product(name: "XCTVapor", package: "vapor")
            ]
        ),
    ]
)
