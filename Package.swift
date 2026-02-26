// swift-tools-version: 6.2

import PackageDescription

extension String {
    static let rfc8446: Self = "RFC 8446"
}

extension Target.Dependency {
    static var rfc8446: Self { .target(name: .rfc8446) }
    static var standards: Self { .product(name: "Standard Library Extensions", package: "swift-standard-library-extensions") }
    static var binary: Self { .product(name: "Binary Primitives", package: "swift-binary-primitives") }
    static var incits41986: Self { .product(name: "ASCII", package: "swift-ascii") }
}

let package = Package(
    name: "swift-rfc-8446",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26)
    ],
    products: [
        .library(name: "RFC 8446", targets: ["RFC 8446"])
    ],
    dependencies: [
        .package(path: "../../swift-primitives/swift-standard-library-extensions"),
        .package(path: "../../swift-primitives/swift-binary-primitives"),
        .package(path: "../../swift-foundations/swift-ascii")
    ],
    targets: [
        .target(
            name: "RFC 8446",
            dependencies: [
                .standards,
                .binary,
                .incits41986
            ]
        ),
        .testTarget(
            name: "RFC 8446 Tests",
            dependencies: [
                "RFC 8446",
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
        .enableExperimentalFeature("SuppressedAssociatedTypesWithDefaults"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
