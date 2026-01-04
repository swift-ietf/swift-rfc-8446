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

// RFC_8446.Extension.NamedGroup.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.7: Supported Groups

extension RFC_8446.Extension {
    /// Named Group (Supported Groups)
    ///
    /// Identifies the elliptic curve or finite field DH group.
    public struct NamedGroup: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Creates a NamedGroup WITHOUT validation
        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }
    }
}

// MARK: - Elliptic Curves

extension RFC_8446.Extension.NamedGroup {
    /// secp256r1 (0x0017)
    public static let secp256r1 = Self(__unchecked: (), rawValue: 0x0017)

    /// secp384r1 (0x0018)
    public static let secp384r1 = Self(__unchecked: (), rawValue: 0x0018)

    /// secp521r1 (0x0019)
    public static let secp521r1 = Self(__unchecked: (), rawValue: 0x0019)

    /// x25519 (0x001D)
    public static let x25519 = Self(__unchecked: (), rawValue: 0x001D)

    /// x448 (0x001E)
    public static let x448 = Self(__unchecked: (), rawValue: 0x001E)
}

// MARK: - Finite Field Groups

extension RFC_8446.Extension.NamedGroup {
    /// ffdhe2048 (0x0100)
    public static let ffdhe2048 = Self(__unchecked: (), rawValue: 0x0100)

    /// ffdhe3072 (0x0101)
    public static let ffdhe3072 = Self(__unchecked: (), rawValue: 0x0101)

    /// ffdhe4096 (0x0102)
    public static let ffdhe4096 = Self(__unchecked: (), rawValue: 0x0102)

    /// ffdhe6144 (0x0103)
    public static let ffdhe6144 = Self(__unchecked: (), rawValue: 0x0103)

    /// ffdhe8192 (0x0104)
    public static let ffdhe8192 = Self(__unchecked: (), rawValue: 0x0104)
}
