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

// RFC_8446.Wire.Writer.swift
// swift-rfc-8446
//
// RFC 8446 Section 3: Presentation Language

internal import Binary_Serializable_Primitives

extension RFC_8446.Wire {
    /// Appends a big-endian `uint24` (0...2^24-1). `BinaryInteger` has no
    /// 3-byte form, so the split is manual; arithmetic-domain `Int` internal,
    /// `Byte()` bridge at the append boundary.
    static func appendUInt24<Buffer: RangeReplaceableCollection>(
        _ value: Int,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(UInt8((value >> 16) & 0xFF)))
        buffer.append(Byte(UInt8((value >> 8) & 0xFF)))
        buffer.append(Byte(UInt8(value & 0xFF)))
    }

    /// Serialized byte length of an extensions block's contents (4 envelope
    /// header bytes plus `extension_data` per extension). Used by payload
    /// constructors to validate `uint16` extensions-block bounds up front so
    /// the append helpers below stay within their length-prefix domains.
    static func extensionsBlockLength(_ extensions: [RFC_8446.Extension.Data]) -> Int {
        extensions.reduce(0) { $0 + 4 + $1.data.count }
    }

    /// Appends a `uint8`-length-prefixed opaque vector.
    ///
    /// - Precondition: `bytes.count <= 0xFF`, guaranteed by the validated
    ///   constructors of every caller (violations trap in `UInt8.init`).
    static func appendVector8<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(UInt8(bytes.count)))
        buffer.append(contentsOf: bytes)
    }

    /// Appends a `uint16`-length-prefixed opaque vector.
    ///
    /// - Precondition: `bytes.count <= 0xFFFF`, guaranteed by the validated
    ///   constructors of every caller (violations trap in `UInt16.init`).
    static func appendVector16<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: UInt16(bytes.count).bytes(endianness: .big))
        buffer.append(contentsOf: bytes)
    }

    /// Appends a `uint24`-length-prefixed opaque vector.
    static func appendVector24<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        appendUInt24(bytes.count, into: &buffer)
        buffer.append(contentsOf: bytes)
    }

    /// Appends a `uint16`-length-prefixed block of big-endian `uint16` values.
    static func appendUInt16List<Buffer: RangeReplaceableCollection>(
        _ values: [UInt16],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for value in values {
            block.append(contentsOf: value.bytes(endianness: .big))
        }
        appendVector16(block, into: &buffer)
    }

    /// Appends a `uint16`-length-prefixed extensions block from typed
    /// ``RFC_8446/Extension/Data`` envelopes.
    static func appendExtensions<Buffer: RangeReplaceableCollection>(
        _ extensions: [RFC_8446.Extension.Data],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for ext in extensions {
            RFC_8446.Extension.Data.serialize(ext, into: &block)
        }
        appendVector16(block, into: &buffer)
    }
}
