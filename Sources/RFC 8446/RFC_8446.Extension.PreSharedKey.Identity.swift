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

// RFC_8446.Extension.PreSharedKey.Identity.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.11: Pre-Shared Key Extension

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.PreSharedKey {
    /// A single `PskIdentity`.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque identity<1..2^16-1>;
    ///     uint32 obfuscated_ticket_age;
    /// } PskIdentity;
    /// ```
    public struct Identity: Sendable, Hashable {
        /// A label for a key (a ticket or external PSK label).
        public let identity: [Byte]

        /// The obfuscated ticket age (0 for externally provisioned PSKs).
        public let obfuscatedTicketAge: UInt32

        /// Creates a PSK identity.
        ///
        /// - Throws: `Error.invalidIdentityLength` if `identity` is outside
        ///   1...65535 bytes.
        public init(
            identity: [Byte],
            obfuscatedTicketAge: UInt32
        ) throws(RFC_8446.Extension.PreSharedKey.Error) {
            guard (1...0xFFFF).contains(identity.count) else {
                throw .invalidIdentityLength(identity.count)
            }
            self.identity = identity
            self.obfuscatedTicketAge = obfuscatedTicketAge
        }

        /// Creates a PSK identity WITHOUT validation (parse path).
        init(__unchecked: Void, identity: [Byte], obfuscatedTicketAge: UInt32) {
            self.identity = identity
            self.obfuscatedTicketAge = obfuscatedTicketAge
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.PreSharedKey.Identity: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ identity: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector16(identity.identity, into: &buffer)
        buffer.append(contentsOf: identity.obfuscatedTicketAge.bytes(endianness: .big))
    }
}

// MARK: - Wire Decoding

extension RFC_8446.Wire.Reader {
    /// Reads one ``RFC_8446/Extension/PreSharedKey/Identity`` from the cursor.
    mutating func pskIdentity() throws(RFC_8446.Wire.Error)
        -> RFC_8446.Extension.PreSharedKey.Identity
    {
        let identity = try vector16()
        let age = try uint32()
        return RFC_8446.Extension.PreSharedKey.Identity(
            __unchecked: (),
            identity: identity,
            obfuscatedTicketAge: age
        )
    }
}
