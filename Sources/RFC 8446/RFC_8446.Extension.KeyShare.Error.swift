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

// RFC_8446.Extension.KeyShare.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.8: Key Share

extension RFC_8446.Extension.KeyShare {
    /// Errors raised when parsing any form of `key_share`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before an entry or field was complete.
        case truncated

        /// Bytes remained after the payload.
        case trailingData(_ remaining: Int)

        /// The key_exchange length is outside 1...65531 (envelope-fitting spec bounds).
        case invalidKeyExchangeLength(_ count: Int)

        /// The serialized client_shares block exceeds its uint16 bound.
        case clientSharesTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.KeyShare.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS key_share truncated"

        case .trailingData(let remaining):
            return "TLS key_share has \(remaining) trailing bytes"

        case .invalidKeyExchangeLength(let count):
            return "TLS key_share key_exchange length invalid: \(count) bytes (expected 1...65531)"

        case .clientSharesTooLong(let byteCount):
            return "TLS key_share client_shares too long: \(byteCount) bytes (max 65533)"
        }
    }
}
