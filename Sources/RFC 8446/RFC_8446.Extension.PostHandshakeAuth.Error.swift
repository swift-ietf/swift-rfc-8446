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

// RFC_8446.Extension.PostHandshakeAuth.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.6: Post-Handshake Client Authentication

extension RFC_8446.Extension.PostHandshakeAuth {
    /// Errors raised when parsing a post_handshake_auth payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was non-empty (post_handshake_auth has an empty body).
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.PostHandshakeAuth.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS post_handshake_auth has \(remaining) trailing bytes (body must be empty)"
        }
    }
}
