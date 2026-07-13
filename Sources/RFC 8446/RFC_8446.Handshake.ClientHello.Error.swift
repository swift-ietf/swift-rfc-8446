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
    }
}

extension RFC_8446.Handshake.ClientHello.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS ClientHello truncated"
        case .trailingData(let remaining):
            return "TLS ClientHello has \(remaining) trailing bytes"
        }
    }
}
