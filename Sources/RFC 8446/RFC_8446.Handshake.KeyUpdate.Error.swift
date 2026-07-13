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

// RFC_8446.Handshake.KeyUpdate.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.6.3: Key and Initialization Vector Update

extension RFC_8446.Handshake.KeyUpdate {
    /// Errors raised when parsing a KeyUpdate payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input was empty (no `request_update` byte).
        case truncated

        /// Bytes remained after the `request_update` byte.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.KeyUpdate.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS KeyUpdate truncated"
        case .trailingData(let remaining):
            return "TLS KeyUpdate has \(remaining) trailing bytes"
        }
    }
}
