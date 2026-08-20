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
        .product(name: "Binary Primitives", package: "swift-binary-primitives")
    }
    static var incits41986: Self {
        .product(name: "ASCII Primitives", package: "swift-ascii-primitives")
    }
    static var radixFormat: Self {
        .product(name: "Radix Formatter Primitives", package: "swift-radix-formatter-primitives")
    }
    static var binarySerializable: Self {
        .product(
            name: "Binary Serializable Primitives",
            package: "swift-binary-serializer-primitives"
        )
    }
    // TEST-TARGET-ONLY: blessed apple/swift-crypto backs the RFC 8448
    // full-chain key-schedule witness. The core "RFC 8446" target never
    // depends on this — the test target adapts swift-crypto INTO the
    // KeySchedule.Witness closures.
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
            url: "https://github.com/swift-primitives/swift-standard-library-extensions.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-primitives/swift-binary-primitives.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-primitives/swift-ascii-primitives.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-primitives/swift-byte-primitives.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-primitives/swift-radix-formatter-primitives.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-primitives/swift-binary-serializer-primitives.git",
            branch: "main"
        ),
        // TEST-TARGET-ONLY dependency (see the `crypto` Target.Dependency
        // helper). Consumed exclusively by "RFC 8446 Tests"; no core target
        // depends on it.
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
                    name: "Byte Primitives Standard Library Integration",
                    package: "swift-byte-primitives"
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
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
