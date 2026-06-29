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

// RFC_8446.Alert.swift
// swift-rfc-8446
//
// RFC 8446 Section 6: Alert Protocol

public import Binary_Serializable_Primitives

extension RFC_8446 {
    /// TLS Alert
    ///
    /// Alerts convey the severity of the message and a description of the alert.
    /// In TLS 1.3, most alerts are fatal.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     AlertLevel level;
    ///     AlertDescription description;
    /// } Alert;
    /// ```
    public struct Alert: Sendable, Hashable, Codable {
        /// Alert level
        public let level: Level

        /// Alert description
        public let alertDescription: Description

        /// Creates an alert
        public init(level: Level, description: Description) {
            self.level = level
            self.alertDescription = description
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Alert: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ alert: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // Level/Description are enum rawValue UInt8 (separate files out of
        // arc scope); bridge via Byte() at the conformance boundary.
        buffer.append(Byte(alert.level.rawValue))
        buffer.append(Byte(alert.alertDescription.rawValue))
    }
}

// MARK: - Convenience Constructors

extension RFC_8446.Alert {
    /// Creates a fatal alert
    public static func fatal(_ description: Description) -> Self {
        Self(level: .fatal, description: description)
    }

    /// Creates a warning alert
    public static func warning(_ description: Description) -> Self {
        Self(level: .warning, description: description)
    }

    /// Close notify alert (warning level)
    public static var closeNotify: Self {
        Self(level: .warning, description: .closeNotify)
    }
}
