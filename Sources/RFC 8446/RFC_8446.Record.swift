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

// RFC_8446.Record.swift
// swift-rfc-8446
//
// RFC 8446 Section 5.1: Record Layer

public import Binary_Serializable_Primitives

extension RFC_8446 {
    /// TLS Record
    ///
    /// The TLS record layer receives uninterpreted data from higher layers,
    /// fragments it, optionally compresses it, applies a MAC, encrypts, and
    /// transmits the result.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     ContentType type;
    ///     ProtocolVersion legacy_record_version;
    ///     uint16 length;
    ///     opaque fragment[TLSPlaintext.length];
    /// } TLSPlaintext;
    /// ```
    ///
    /// ## TLS 1.3 Changes
    ///
    /// In TLS 1.3:
    /// - `legacy_record_version` is always 0x0303 (TLS 1.2)
    /// - The actual version is negotiated via supported_versions extension
    /// - Maximum fragment length is 2^14 (16384) bytes
    /// - With encryption overhead, maximum record is 2^14 + 256 bytes
    public struct Record: Sendable, Hashable {
        /// Content type
        public let contentType: ContentType

        /// Legacy record version (always TLS 1.2 in TLS 1.3)
        public let legacyVersion: ProtocolVersion

        /// Record fragment (plaintext or ciphertext, opaque byte-domain)
        public let fragment: [Byte]

        /// Creates a TLS record
        ///
        /// - Parameters:
        ///   - contentType: The content type
        ///   - fragment: The record payload
        /// - Throws: `Error.fragmentTooLarge` if fragment exceeds maximum size
        public init(
            contentType: ContentType,
            fragment: [Byte]
        ) throws(Error) {
            guard fragment.count <= Limits.maxPlaintextLength else {
                throw Error.fragmentTooLarge(fragment.count)
            }
            self.contentType = contentType
            self.legacyVersion = .legacy
            self.fragment = fragment
        }

        // Stdlib-interop UInt8 forwarder lives in `RFC 8446 Standard Library
        // Integration` per [API-BYTE-007].

        /// Creates a TLS record WITHOUT validation
        init(
            __unchecked: Void,
            contentType: ContentType,
            legacyVersion: ProtocolVersion,
            fragment: [Byte]
        ) {
            self.contentType = contentType
            self.legacyVersion = legacyVersion
            self.fragment = fragment
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Record: Binary.Serializable {
    /// Serializes the TLS record to wire format
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ record: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // Content type (ContentType.rawValue stays UInt8 in separate file
        // scope; bridge via Byte()).
        buffer.append(Byte(record.contentType.rawValue))

        // Legacy version (UInt16 stays — assumed; Byte-primary
        // bytes(endianness:)).
        buffer.append(contentsOf: record.legacyVersion.rawValue.bytes(endianness: .big))

        // Length (UInt16 stays — assumed; Byte-primary bytes(endianness:)).
        let length = UInt16(record.fragment.count)
        buffer.append(contentsOf: length.bytes(endianness: .big))

        // Fragment (opaque byte-domain payload, already [Byte])
        buffer.append(contentsOf: record.fragment)
    }

    /// Parses a TLS record from wire format
    ///
    /// - Parameter bytes: At least 5 bytes (header) plus fragment
    /// - Throws: `Error` if bytes are malformed
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.count >= Limits.headerSize else {
            throw Error.truncated(bytes.count)
        }

        var iterator = bytes.makeIterator()

        // Internal arithmetic-domain UInt8 byte stream; bridge from Byte via
        // .underlying at the conformance boundary.
        func next() -> UInt8 {
            iterator.next()!.underlying
        }

        // Content type
        let ct = next()
        self.contentType = RFC_8446.ContentType(rawValue: ct)

        // Legacy version
        let vHi = next()
        let vLo = next()
        self.legacyVersion = RFC_8446.ProtocolVersion(rawValue: (UInt16(vHi) << 8) | UInt16(vLo))

        // Length
        let lHi = next()
        let lLo = next()
        let length = (Int(lHi) << 8) | Int(lLo)

        guard length <= Limits.maxCiphertextLength else {
            throw Error.fragmentTooLarge(length)
        }

        guard bytes.count >= Limits.headerSize + length else {
            throw Error.truncated(bytes.count)
        }

        // Fragment (opaque byte-domain payload)
        var fragment: [Byte] = []
        fragment.reserveCapacity(length)
        for _ in 0..<length {
            fragment.append(Byte(next()))
        }
        self.fragment = fragment
    }
}
