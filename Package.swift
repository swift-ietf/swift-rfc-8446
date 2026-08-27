// swift-tools-version: 6.4

import PackageDescription

extension String {
    static let rfc8446: Self = "RFC 8446"
}

extension Target.Dependency {
    static var rfc8446: Self { .target(name: .rfc8446) }
    static var standards: Self {
        .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions")
    }
    static var binary: Self {
        .product(name: "Binary", package: "swift-binary")
    }
    static var incits41986: Self {
        .product(name: "ASCII", package: "swift-ascii")
    }
    static var radixFormat: Self {
        .product(name: "Radix Formatter", package: "swift-radix-formatter")
    }
    static var binarySerializable: Self {
        .product(
            name: "Binary Serializable",
            package: "swift-binary-serializer"
        )
    }

    static var crypto: Self { .product(name: "Crypto", package: "swift-crypto") }
}

let package = Package(
    name: "swift-rfc-8446",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: "RFC 8446", targets: ["RFC 8446"]),
        .library(
            name: "RFC 8446 Standard Library Integration",
            targets: ["RFC 8446 Standard Library Integration"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-molecules/swift-standard-library-extensions.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-binary.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-ascii.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-byte.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-radix-formatter.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-binary-serializer.git",
            branch: "main"
        ),

        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(
            name: "RFC 8446",
            dependencies: [
                .standards,
                .binary,
                .incits41986,
                .radixFormat,
                .binarySerializable,
            ]
        ),
        .target(
            name: "RFC 8446 Standard Library Integration",
            dependencies: [
                "RFC 8446",
                .product(
                    name: "Byte Standard Library Integration",
                    package: "swift-byte"
                ),
            ]
        ),
        .testTarget(
            name: "RFC 8446 Tests",
            dependencies: [
                "RFC 8446",
                .crypto,
            ]
        ),
        .testTarget(
            name: "RFC 8446 Standard Library Integration Tests",
            dependencies: [
                "RFC 8446",
                "RFC 8446 Standard Library Integration",
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String {
    var tests: Self { self + " Tests" }
}

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("Lifetimes"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
