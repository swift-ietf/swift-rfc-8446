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

// RFC_8446.Handshake.Message.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4: Handshake Protocol

extension RFC_8446.Handshake.Message {
    /// Errors raised when parsing a handshake message envelope.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the 4-byte header plus body were complete.
        case truncated

        /// The `uint24` length field did not match the bytes actually present.
        case lengthMismatch(_ declared: Int, _ available: Int)
    }
}

extension RFC_8446.Handshake.Message.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS handshake message truncated"
        case .lengthMismatch(let declared, let available):
            return "TLS handshake message length mismatch: declared \(declared), available \(available)"
        }
    }
}
