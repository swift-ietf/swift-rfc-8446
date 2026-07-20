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

// RFC_8446.Handshake.Certificate.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.2: Certificate

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Certificate handshake payload, conveying the endpoint's certificate
    /// chain.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque certificate_request_context<0..2^8-1>;
    ///     CertificateEntry certificate_list<0..2^24-1>;
    /// } Certificate;
    /// ```
    public struct Certificate: Sendable, Hashable {
        /// `certificate_request_context` (zero length for server auth).
        public let certificateRequestContext: [Byte]

        /// The chain of ``Entry`` values, end-entity certificate first.
        public let certificateList: [Entry]

        /// Creates a Certificate payload.
        ///
        /// - Throws: `Error.invalidContextLength` if the context exceeds 255
        ///   bytes; `Error.certificateListTooLong` if the serialized
        ///   `certificate_list` block exceeds the `uint24` bound within the
        ///   handshake body ceiling.
        public init(certificateRequestContext: [Byte] = [], certificateList: [Entry]) throws(Error) {
            guard certificateRequestContext.count <= 0xFF else {
                throw Error.invalidContextLength(certificateRequestContext.count)
            }
            let blockLength = certificateList.reduce(0) {
                $0 + 3 + $1.certificateData.count + 2 + RFC_8446.Wire.extensionsBlockLength($1.extensions)
            }
            guard blockLength <= 0xFF_FFFF - 4 - certificateRequestContext.count else {
                throw Error.certificateListTooLong(blockLength)
            }
            self.certificateRequestContext = certificateRequestContext
            self.certificateList = certificateList
        }

        /// Creates a Certificate payload WITHOUT validation (parse path).
        init(__unchecked: Void, certificateRequestContext: [Byte], certificateList: [Entry]) {
            self.certificateRequestContext = certificateRequestContext
            self.certificateList = certificateList
        }

        /// The handshake message type for this payload (`certificate`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .certificate

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.Certificate: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ certificate: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector8(certificate.certificateRequestContext, into: &buffer)

        // certificate_list is a uint24-length-prefixed sequence of entries.
        var entriesBlock: [Byte] = []
        for entry in certificate.certificateList {
            Entry.serialize(entry, into: &entriesBlock)
        }
        RFC_8446.Wire.appendVector24(entriesBlock, into: &buffer)
    }

    /// Parses a Certificate payload body (without the handshake header).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let context = try reader.vector8()
            let entriesBlock = try reader.vector24()
            var sub = RFC_8446.Wire.Reader(entriesBlock)
            var entries: [Entry] = []
            while !sub.isAtEnd {
                entries.append(try sub.certificateEntry())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), certificateRequestContext: context, certificateList: entries)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
