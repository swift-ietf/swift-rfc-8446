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

// RFC_8446.Handshake.ServerHello.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.1.3: Server Hello

extension RFC_8446.Handshake.ServerHello {
    /// Errors raised when parsing a ServerHello payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the extensions block.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.ServerHello.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS ServerHello truncated"
        case .trailingData(let remaining):
            return "TLS ServerHello has \(remaining) trailing bytes"
        }
    }
}
