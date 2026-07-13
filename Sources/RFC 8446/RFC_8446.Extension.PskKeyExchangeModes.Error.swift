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

// RFC_8446.Extension.PskKeyExchangeModes.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.9: Pre-Shared Key Exchange Modes

extension RFC_8446.Extension.PskKeyExchangeModes {
    /// Errors raised when parsing a psk_key_exchange_modes payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the mode list was complete.
        case truncated

        /// Bytes remained after the mode list.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.PskKeyExchangeModes.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS psk_key_exchange_modes truncated"
        case .trailingData(let remaining):
            return "TLS psk_key_exchange_modes has \(remaining) trailing bytes"
        }
    }
}
