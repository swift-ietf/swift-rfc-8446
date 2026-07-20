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

// RFC_8446.Handshake.EncryptedExtensions.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.3.1: Encrypted Extensions

extension RFC_8446.Handshake.EncryptedExtensions {
    /// Errors raised when parsing an EncryptedExtensions payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the extensions block was complete.
        case truncated

        /// Bytes remained after the extensions block.
        case trailingData(_ remaining: Int)

        /// The serialized extensions block exceeds 65535 bytes.
        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.EncryptedExtensions.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS EncryptedExtensions truncated"
        case .trailingData(let remaining):
            return "TLS EncryptedExtensions has \(remaining) trailing bytes"
        case .extensionsTooLong(let byteCount):
            return "TLS EncryptedExtensions extensions too long: \(byteCount) bytes (max 65535)"
        }
    }
}
