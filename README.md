# swift-rfc-8446

![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

The TLS 1.3 handshake and record structures of RFC 8446.

## Standard Reference

- **RFC**: 8446
- **Title**: The Transport Layer Security (TLS) Protocol Version 1.3

## Installation

Add the package to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/swift-ietf/swift-rfc-8446.git", from: "0.0.1")
]
```

Add the product to a target that needs it:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "RFC 8446", package: "swift-rfc-8446")
    ]
)
```

## License

Apache 2.0. See [LICENSE.md](LICENSE.md).
