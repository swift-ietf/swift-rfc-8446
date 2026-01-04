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

// RFC_8446.ContentType.swift
// swift-rfc-8446
//
// RFC 8446 Section 5.1: Record Layer

extension RFC_8446 {
    /// TLS Record Content Type
    ///
    /// Identifies the type of data contained in the TLS record.
    ///
    /// ## Content Types
    ///
    /// - invalid (0): Reserved, not used
    /// - change_cipher_spec (20): Legacy compatibility
    /// - alert (21): Alert messages
    /// - handshake (22): Handshake messages
    /// - application_data (23): Encrypted application data
    public struct ContentType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a ContentType WITHOUT validation
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Invalid (0) - reserved
        public static let invalid = Self(__unchecked: (), rawValue: 0)

        /// Change Cipher Spec (20) - legacy compatibility
        ///
        /// In TLS 1.3, this is only used for middlebox compatibility.
        public static let changeCipherSpec = Self(__unchecked: (), rawValue: 20)

        /// Alert (21)
        public static let alert = Self(__unchecked: (), rawValue: 21)

        /// Handshake (22)
        public static let handshake = Self(__unchecked: (), rawValue: 22)

        /// Application Data (23)
        public static let applicationData = Self(__unchecked: (), rawValue: 23)

        /// Heartbeat (24) - RFC 6520
        public static let heartbeat = Self(__unchecked: (), rawValue: 24)
    }
}

extension RFC_8446.ContentType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "invalid"
        case 20: return "change_cipher_spec"
        case 21: return "alert"
        case 22: return "handshake"
        case 23: return "application_data"
        case 24: return "heartbeat"
        default: return "content_type(\(rawValue))"
        }
    }
}
