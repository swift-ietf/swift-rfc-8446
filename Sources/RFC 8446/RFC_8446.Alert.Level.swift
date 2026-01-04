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

// RFC_8446.Alert.Level.swift
// swift-rfc-8446
//
// RFC 8446 Section 6: Alert Protocol

extension RFC_8446.Alert {
    /// Alert Level
    ///
    /// In TLS 1.3, most alerts are fatal. The warning level is only used
    /// for close_notify and user_canceled.
    public struct Level: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a Level WITHOUT validation
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }
}

// MARK: - Standard Levels

extension RFC_8446.Alert.Level {
    /// Warning (1)
    public static let warning = Self(__unchecked: (), rawValue: 1)

    /// Fatal (2)
    public static let fatal = Self(__unchecked: (), rawValue: 2)
}
