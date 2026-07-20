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

// RFC_8446.Handshake.NewSessionTicket.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.6.1: New Session Ticket Message

extension RFC_8446.Handshake.NewSessionTicket {
    /// Errors raised when parsing a NewSessionTicket payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the extensions block.
        case trailingData(_ remaining: Int)

        /// The ticket_nonce exceeds 255 bytes.
        case invalidNonceLength(_ count: Int)

        /// The ticket is outside 1...65535 bytes.
        case invalidTicketLength(_ count: Int)

        /// The serialized extensions block exceeds 65534 bytes.
        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.NewSessionTicket.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS NewSessionTicket truncated"
        case .trailingData(let remaining):
            return "TLS NewSessionTicket has \(remaining) trailing bytes"
        case .invalidNonceLength(let count):
            return "TLS NewSessionTicket nonce length invalid: \(count) bytes (max 255)"
        case .invalidTicketLength(let count):
            return "TLS NewSessionTicket ticket length invalid: \(count) bytes (expected 1...65535)"
        case .extensionsTooLong(let byteCount):
            return "TLS NewSessionTicket extensions too long: \(byteCount) bytes (max 65534)"
        }
    }
}
