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

// RFC_8446.Handshake.Certificate.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.2: Certificate

extension RFC_8446.Handshake.Certificate {
    /// Errors raised when parsing a Certificate payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field or entry was complete.
        case truncated

        /// Bytes remained after the certificate list.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.Certificate.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS Certificate truncated"
        case .trailingData(let remaining):
            return "TLS Certificate has \(remaining) trailing bytes"
        }
    }
}
