// swift-tools-version: 6.4

import PackageDescription

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
    traits: [
        .trait(
            name: "RFC8446StandardLibraryIntegration",
            description: "RFC 8446 Standard Library Integration and the dependencies only it needs"
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-atoms/swift-standard-library-extensions.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-binary.git",
            branch: "main",
            traits: ["Serializer"]
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-ascii.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-byte.git",
            branch: "main"
        ),

        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/swift-atoms/swift-formatter.git", branch: "main", traits: ["Radix"]),
    ],
    targets: [
        .target(
            name: "RFC 8446",
            dependencies: [
                .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions"),
                .product(name: "Binary", package: "swift-binary"),
                .product(name: "ASCII", package: "swift-ascii"),
                .product(name: "Formatter", package: "swift-formatter"),
            ]
        ),
        .target(
            name: "RFC 8446 Standard Library Integration",
            dependencies: [
                .target(name: "RFC 8446"),
                .product(
                    name: "Byte",
                    package: "swift-byte",
                    condition: .when(traits: ["RFC8446StandardLibraryIntegration"])
                ),
            ]
        ),
        .testTarget(
            name: "RFC 8446 Tests",
            dependencies: [
                .target(name: "RFC 8446"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Binary", package: "swift-binary"),
            ]
        ),
        .testTarget(
            name: "RFC 8446 Standard Library Integration Tests",
            dependencies: [
                .target(name: "RFC 8446"),
                .target(name: "RFC 8446 Standard Library Integration"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    target.swiftSettings =
        (target.swiftSettings ?? []) + [
            .strictMemorySafety(),
            .enableUpcomingFeature("ExistentialAny"),
            .enableUpcomingFeature("InternalImportsByDefault"),
            .enableUpcomingFeature("MemberImportVisibility"),
            .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
            .enableUpcomingFeature("InferIsolatedConformances"),
            .enableExperimentalFeature("Lifetimes"),
            .treatAllWarnings(as: .error),
        ]
}
