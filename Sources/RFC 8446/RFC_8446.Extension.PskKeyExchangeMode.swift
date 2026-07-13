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

// RFC_8446.Extension.PskKeyExchangeMode.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.9: Pre-Shared Key Exchange Modes

extension RFC_8446.Extension {
    /// `PskKeyExchangeMode`, the PSK key establishment mode.
    ///
    /// ```
    /// enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
    /// ```
    public struct PskKeyExchangeMode: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a PskKeyExchangeMode WITHOUT validation.
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// psk_ke (0) — PSK-only key establishment.
        public static let pskKe = Self(__unchecked: (), rawValue: 0)

        /// psk_dhe_ke (1) — PSK with (EC)DHE key establishment.
        public static let pskDheKe = Self(__unchecked: (), rawValue: 1)
    }
}

extension RFC_8446.Extension.PskKeyExchangeMode: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "psk_ke"
        case 1: return "psk_dhe_ke"
        default: return "psk_key_exchange_mode(\(rawValue))"
        }
    }
}
