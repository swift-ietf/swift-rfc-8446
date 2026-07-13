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

// RFC_8446.Handshake.CertificateVerify.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.3: Certificate Verify

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Certificate Verify handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     SignatureScheme algorithm;
    ///     opaque signature<0..2^16-1>;
    /// } CertificateVerify;
    /// ```
    public struct CertificateVerify: Sendable, Hashable {
        /// The signature `algorithm` used.
        public let algorithm: RFC_8446.Extension.SignatureScheme

        /// The `signature` bytes (opaque byte-domain).
        public let signature: [Byte]

        /// Creates a CertificateVerify payload.
        public init(algorithm: RFC_8446.Extension.SignatureScheme, signature: [Byte]) {
            self.algorithm = algorithm
            self.signature = signature
        }

        /// The handshake message type for this payload (`certificate_verify`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .certificateVerify

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.CertificateVerify: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ verify: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: verify.algorithm.rawValue.bytes(endianness: .big))
        RFC_8446.Wire.appendVector16(verify.signature, into: &buffer)
    }

    /// Parses a CertificateVerify payload body (without the handshake header).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let algorithm = try reader.uint16()
            let signature = try reader.vector16()
            try reader.expectEnd()
            self.init(
                algorithm: RFC_8446.Extension.SignatureScheme(rawValue: algorithm),
                signature: signature
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
