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

// RFC_8446.Wire.Reader.swift
// swift-rfc-8446
//
// RFC 8446 Section 3: Presentation Language

internal import Binary_Serializable_Primitives

extension RFC_8446.Wire {
    /// A forward cursor over a byte buffer that decodes the TLS
    /// presentation-language forms.
    ///
    /// The cursor advances as fields are read; length-prefixed vectors are
    /// bounds-checked against the remaining input. All reads throw
    /// ``RFC_8446/Wire/Error`` on exhaustion or overflow.
    struct Reader {
        /// The backing byte buffer (arithmetic-domain reads bridge via
        /// `Byte.underlying`).
        private let bytes: [Byte]

        /// The current read offset.
        private(set) var index: Int

        /// Creates a reader positioned at the start of `bytes`.
        init(_ bytes: [Byte]) {
            self.bytes = bytes
            self.index = 0
        }

        /// The number of unread bytes remaining.
        var remaining: Int { bytes.count - index }

        /// Whether every byte has been consumed.
        var isAtEnd: Bool { index >= bytes.count }

        /// Reads a single `uint8` (arithmetic-domain).
        mutating func byte() throws(RFC_8446.Wire.Error) -> UInt8 {
            guard index < bytes.count else { throw .truncated }
            defer { index += 1 }
            return bytes[index].underlying
        }

        /// Reads a big-endian `uint16`.
        mutating func uint16() throws(RFC_8446.Wire.Error) -> UInt16 {
            let hi = try byte()
            let lo = try byte()
            return (UInt16(hi) << 8) | UInt16(lo)
        }

        /// Reads a big-endian `uint24` as an `Int` (0...2^24-1).
        mutating func uint24() throws(RFC_8446.Wire.Error) -> Int {
            let a = try byte()
            let b = try byte()
            let c = try byte()
            return (Int(a) << 16) | (Int(b) << 8) | Int(c)
        }

        /// Reads a big-endian `uint32`.
        mutating func uint32() throws(RFC_8446.Wire.Error) -> UInt32 {
            let a = try byte()
            let b = try byte()
            let c = try byte()
            let d = try byte()
            return (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | UInt32(d)
        }

        /// Reads `count` raw bytes (opaque byte-domain).
        mutating func take(_ count: Int) throws(RFC_8446.Wire.Error) -> [Byte] {
            guard count >= 0 else { throw .lengthOverflow }
            guard remaining >= count else { throw .truncated }
            let slice = bytes[index..<index + count]
            index += count
            return Array(slice)
        }

        /// Consumes and returns every remaining byte.
        mutating func rest() -> [Byte] {
            let slice = bytes[index..<bytes.count]
            index = bytes.count
            return Array(slice)
        }

        /// Reads a `uint8`-length-prefixed opaque vector (`opaque x<0..2^8-1>`).
        mutating func vector8() throws(RFC_8446.Wire.Error) -> [Byte] {
            let count = Int(try byte())
            return try take(count)
        }

        /// Reads a `uint16`-length-prefixed opaque vector (`opaque x<0..2^16-1>`).
        mutating func vector16() throws(RFC_8446.Wire.Error) -> [Byte] {
            let count = Int(try uint16())
            return try take(count)
        }

        /// Reads a `uint24`-length-prefixed opaque vector (`opaque x<0..2^24-1>`).
        mutating func vector24() throws(RFC_8446.Wire.Error) -> [Byte] {
            let count = try uint24()
            return try take(count)
        }

        /// Reads a `uint16`-length-prefixed block of big-endian `uint16` values.
        ///
        /// Models the `T x<2..2^16-2>` list forms used by
        /// `SignatureSchemeList`, `NamedGroupList`, and the ClientHello
        /// `supported_versions` list.
        mutating func uint16List() throws(RFC_8446.Wire.Error) -> [UInt16] {
            let block = try vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var values: [UInt16] = []
            while !sub.isAtEnd {
                values.append(try sub.uint16())
            }
            return values
        }

        /// Reads a `uint16`-length-prefixed extensions block into typed
        /// ``RFC_8446/Extension/Data`` envelopes.
        mutating func extensions() throws(RFC_8446.Wire.Error) -> [RFC_8446.Extension.Data] {
            let block = try vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var result: [RFC_8446.Extension.Data] = []
            while !sub.isAtEnd {
                let type = try sub.uint16()
                let data = try sub.vector16()
                result.append(
                    RFC_8446.Extension.Data(
                        type: RFC_8446.Extension.ExtensionType(rawValue: type),
                        data: data
                    )
                )
            }
            return result
        }

        /// Asserts the reader has consumed all of its input.
        func expectEnd() throws(RFC_8446.Wire.Error) {
            guard isAtEnd else { throw .trailingData(remaining) }
        }
    }
}
