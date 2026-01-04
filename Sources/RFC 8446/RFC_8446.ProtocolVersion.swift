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

// RFC_8446.ProtocolVersion.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.1.2: Protocol Version

extension RFC_8446 {
    /// TLS Protocol Version
    ///
    /// Protocol versions are represented as {major, minor} pairs encoded as
    /// a 16-bit value (major << 8 | minor).
    ///
    /// ## TLS 1.3 Changes
    ///
    /// In TLS 1.3, the record layer version is frozen at TLS 1.2 (0x0303) for
    /// backwards compatibility. The actual negotiated version is communicated
    /// via the supported_versions extension.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     uint8 major;
    ///     uint8 minor;
    /// } ProtocolVersion;
    /// ```
    public struct ProtocolVersion: RawRepresentable, Sendable, Hashable, Codable, Comparable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Creates a protocol version from major and minor components
        public init(major: UInt8, minor: UInt8) {
            self.rawValue = (UInt16(major) << 8) | UInt16(minor)
        }

        /// Creates a ProtocolVersion WITHOUT validation
        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Major version component
        public var major: UInt8 {
            UInt8(rawValue >> 8)
        }

        /// Minor version component
        public var minor: UInt8 {
            UInt8(rawValue & 0xFF)
        }

        // MARK: - Known Versions

        /// TLS 1.0 (0x0301)
        public static let tls1_0 = Self(__unchecked: (), rawValue: 0x0301)

        /// TLS 1.1 (0x0302)
        public static let tls1_1 = Self(__unchecked: (), rawValue: 0x0302)

        /// TLS 1.2 (0x0303)
        public static let tls1_2 = Self(__unchecked: (), rawValue: 0x0303)

        /// TLS 1.3 (0x0304)
        public static let tls1_3 = Self(__unchecked: (), rawValue: 0x0304)

        /// Legacy version used in record layer for TLS 1.3
        ///
        /// Per RFC 8446 Section 5.1, the record layer version is set to 0x0303
        /// (TLS 1.2) for backwards compatibility.
        public static let legacy = Self.tls1_2

        public static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }
}

extension RFC_8446.ProtocolVersion: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0x0300: return "SSL 3.0"
        case 0x0301: return "TLS 1.0"
        case 0x0302: return "TLS 1.1"
        case 0x0303: return "TLS 1.2"
        case 0x0304: return "TLS 1.3"
        default: return "TLS \(major).\(minor)"
        }
    }
}
