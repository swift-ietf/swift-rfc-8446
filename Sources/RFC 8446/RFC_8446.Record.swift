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

        /// Record fragment (plaintext or ciphertext)
        public let fragment: [UInt8]

        /// Creates a TLS record
        ///
        /// - Parameters:
        ///   - contentType: The content type
        ///   - fragment: The record payload
        /// - Throws: `Error.fragmentTooLarge` if fragment exceeds maximum size
        public init(
            contentType: ContentType,
            fragment: [UInt8]
        ) throws(Error) {
            guard fragment.count <= Limits.maxPlaintextLength else {
                throw Error.fragmentTooLarge(fragment.count)
            }
            self.contentType = contentType
            self.legacyVersion = .legacy
            self.fragment = fragment
        }

        /// Creates a TLS record WITHOUT validation
        init(
            __unchecked: Void,
            contentType: ContentType,
            legacyVersion: ProtocolVersion,
            fragment: [UInt8]
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
    ) where Buffer.Element == UInt8 {
        // Content type (1 byte)
        buffer.append(record.contentType.rawValue)

        // Legacy version (2 bytes)
        buffer.append(UInt8(record.legacyVersion.rawValue >> 8))
        buffer.append(UInt8(record.legacyVersion.rawValue & 0xFF))

        // Length (2 bytes)
        buffer.append(UInt8(record.fragment.count >> 8))
        buffer.append(UInt8(record.fragment.count & 0xFF))

        // Fragment
        buffer.append(contentsOf: record.fragment)
    }

    /// Parses a TLS record from wire format
    ///
    /// - Parameter bytes: At least 5 bytes (header) plus fragment
    /// - Throws: `Error` if bytes are malformed
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == UInt8 {
        guard bytes.count >= Limits.headerSize else {
            throw Error.truncated(bytes.count)
        }

        var iterator = bytes.makeIterator()

        // Content type
        let ct = iterator.next()!
        self.contentType = RFC_8446.ContentType(rawValue: ct)

        // Legacy version
        let vHi = iterator.next()!
        let vLo = iterator.next()!
        self.legacyVersion = RFC_8446.ProtocolVersion(rawValue: (UInt16(vHi) << 8) | UInt16(vLo))

        // Length
        let lHi = iterator.next()!
        let lLo = iterator.next()!
        let length = (Int(lHi) << 8) | Int(lLo)

        guard length <= Limits.maxCiphertextLength else {
            throw Error.fragmentTooLarge(length)
        }

        guard bytes.count >= Limits.headerSize + length else {
            throw Error.truncated(bytes.count)
        }

        // Fragment
        var fragment: [UInt8] = []
        fragment.reserveCapacity(length)
        for _ in 0..<length {
            fragment.append(iterator.next()!)
        }
        self.fragment = fragment
    }
}
