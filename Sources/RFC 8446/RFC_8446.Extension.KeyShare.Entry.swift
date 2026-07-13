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

// RFC_8446.Extension.KeyShare.Entry.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.8: Key Share

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.KeyShare {
    /// A single key share (`KeyShareEntry`).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     NamedGroup group;
    ///     opaque key_exchange<1..2^16-1>;
    /// } KeyShareEntry;
    /// ```
    public struct Entry: Sendable, Hashable {
        /// The named group for the key being exchanged.
        public let group: RFC_8446.Extension.NamedGroup

        /// The `key_exchange` bytes (opaque byte-domain, group-defined).
        public let keyExchange: [Byte]

        /// Creates a key share entry.
        public init(group: RFC_8446.Extension.NamedGroup, keyExchange: [Byte]) {
            self.group = group
            self.keyExchange = keyExchange
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.KeyShare.Entry: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ entry: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: entry.group.rawValue.bytes(endianness: .big))
        RFC_8446.Wire.appendVector16(entry.keyExchange, into: &buffer)
    }
}

// MARK: - Wire Decoding

extension RFC_8446.Wire.Reader {
    /// Reads one ``RFC_8446/Extension/KeyShare/Entry`` from the cursor.
    mutating func keyShareEntry() throws(RFC_8446.Wire.Error) -> RFC_8446.Extension.KeyShare.Entry {
        let group = try uint16()
        let keyExchange = try vector16()
        return RFC_8446.Extension.KeyShare.Entry(
            group: RFC_8446.Extension.NamedGroup(rawValue: group),
            keyExchange: keyExchange
        )
    }
}
