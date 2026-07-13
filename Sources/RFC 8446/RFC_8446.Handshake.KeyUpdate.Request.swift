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

// RFC_8446.Handshake.KeyUpdate.Request.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.6.3: Key and Initialization Vector Update

extension RFC_8446.Handshake.KeyUpdate {
    /// `KeyUpdateRequest`, indicating whether the peer should respond with its
    /// own KeyUpdate.
    ///
    /// ```
    /// enum {
    ///     update_not_requested(0), update_requested(1), (255)
    /// } KeyUpdateRequest;
    /// ```
    public struct Request: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a Request WITHOUT validation.
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// update_not_requested (0)
        public static let updateNotRequested = Self(__unchecked: (), rawValue: 0)

        /// update_requested (1)
        public static let updateRequested = Self(__unchecked: (), rawValue: 1)
    }
}

extension RFC_8446.Handshake.KeyUpdate.Request: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "update_not_requested"
        case 1: return "update_requested"
        default: return "key_update_request(\(rawValue))"
        }
    }
}
