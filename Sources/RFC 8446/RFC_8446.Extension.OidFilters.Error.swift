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

// RFC_8446.Extension.OidFilters.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.5: OID Filters

extension RFC_8446.Extension.OidFilters {
    /// Errors raised when parsing an oid_filters payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a filter or the list was complete.
        case truncated

        /// Bytes remained after the filters list.
        case trailingData(_ remaining: Int)

        /// A certificate_extension_oid length is outside 1...255.
        case invalidOIDLength(_ count: Int)

        /// A certificate_extension_values length exceeds its uint16 bound.
        case valuesTooLong(_ count: Int)

        /// The serialized filters block exceeds its uint16 bound.
        case filtersTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.OidFilters.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS oid_filters truncated"

        case .trailingData(let remaining):
            return "TLS oid_filters has \(remaining) trailing bytes"

        case .invalidOIDLength(let count):
            return "TLS oid_filters OID length invalid: \(count) bytes (expected 1...255)"

        case .valuesTooLong(let count):
            return "TLS oid_filters values too long: \(count) bytes (max 65535)"

        case .filtersTooLong(let byteCount):
            return "TLS oid_filters too long: \(byteCount) bytes (max 65533)"
        }
    }
}
