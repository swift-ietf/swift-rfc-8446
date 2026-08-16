// ===----------------------------------------------------------------------===//
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of project contributors
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

// RFC_8446.Handshake.ClientHello.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.1.2: Client Hello

extension RFC_8446.Handshake.ClientHello {
    /// Errors raised when parsing a ClientHello payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the extensions block.
        case trailingData(_ remaining: Int)

        /// The random is not exactly 32 bytes.
        case invalidRandomLength(_ count: Int)

        /// The legacy_session_id exceeds 32 bytes.
        case invalidSessionIDLength(_ count: Int)

        /// The cipher_suites count is outside 1...32767.
        case invalidCipherSuiteCount(_ count: Int)

        /// The legacy_compression_methods is outside 1...255 bytes.
        case invalidCompressionMethodsLength(_ count: Int)

        /// The serialized extensions block exceeds 65535 bytes.
        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.ClientHello.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS ClientHello truncated"

        case .trailingData(let remaining):
            return "TLS ClientHello has \(remaining) trailing bytes"

        case .invalidRandomLength(let count):
            return "TLS ClientHello random length invalid: \(count) bytes (expected 32)"

        case .invalidSessionIDLength(let count):
            return "TLS ClientHello legacy_session_id length invalid: \(count) bytes (max 32)"

        case .invalidCipherSuiteCount(let count):
            return "TLS ClientHello cipher_suites count invalid: \(count) (expected 1...32767)"

        case .invalidCompressionMethodsLength(let count):
            return
                "TLS ClientHello legacy_compression_methods length invalid: \(count) bytes (expected 1...255)"

        case .extensionsTooLong(let byteCount):
            return "TLS ClientHello extensions too long: \(byteCount) bytes (max 65535)"
        }
    }
}
