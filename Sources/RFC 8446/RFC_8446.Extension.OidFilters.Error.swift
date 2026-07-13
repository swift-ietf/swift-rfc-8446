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
    }
}

extension RFC_8446.Extension.OidFilters.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS oid_filters truncated"
        case .trailingData(let remaining):
            return "TLS oid_filters has \(remaining) trailing bytes"
        }
    }
}
