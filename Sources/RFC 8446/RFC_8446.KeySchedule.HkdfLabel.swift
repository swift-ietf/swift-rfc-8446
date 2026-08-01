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

// RFC_8446.KeySchedule.HkdfLabel.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1: Key Schedule

public import Binary_Serializable_Primitives

extension RFC_8446.KeySchedule {
    /// The `HkdfLabel` structure fed to `HKDF-Expand` by `HKDF-Expand-Label`.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     uint16 length = Length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// } HkdfLabel;
    /// ```
    ///
    /// ``label`` stores the FULL wire label including the ``prefix`` (`"tls13 "`);
    /// use ``init(length:label:context:)-(UInt16,_,_)`` with a bare spec label to
    /// prepend the prefix automatically.
    public struct HkdfLabel: Sendable, Hashable {
        /// The requested output length, `Length`.
        public let length: UInt16

        /// The full wire label (`"tls13 " + Label`), 7...255 bytes.
        public let label: [Byte]

        /// The context (typically a transcript hash or empty), 0...255 bytes.
        public let context: [Byte]

        /// Creates an HkdfLabel from a full wire label (including the prefix).
        public init(length: UInt16, label: [Byte], context: [Byte]) {
            self.length = length
            self.label = label
            self.context = context
        }

        /// Creates an HkdfLabel from a bare spec label, prepending ``prefix``.
        ///
        /// For example `HkdfLabel(length: 32, label: "derived", context: hash)`
        /// yields the full label `"tls13 derived"`.
        public init(length: UInt16, label: some StringProtocol, context: [Byte]) {
            var full = Self.prefix
            full.append(contentsOf: label.utf8.map(Byte.init))
            self.init(length: length, label: full, context: context)
        }

        /// The `"tls13 "` label prefix prepended to every TLS 1.3 HKDF label.
        public static let prefix: [Byte] = Array("tls13 ".utf8).map(Byte.init)
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.KeySchedule.HkdfLabel: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.length.bytes(endianness: .big))
        RFC_8446.Wire.appendVector8(value.label, into: &buffer)
        RFC_8446.Wire.appendVector8(value.context, into: &buffer)
    }

    /// Parses an `HkdfLabel` from wire format.
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let length = try reader.uint16()
            let label = try reader.vector8()
            let context = try reader.vector8()
            try reader.expectEnd()
            self.init(length: length, label: label, context: context)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
