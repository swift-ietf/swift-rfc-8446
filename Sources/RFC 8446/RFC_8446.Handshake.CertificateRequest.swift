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

// RFC_8446.Handshake.CertificateRequest.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.3.2: Certificate Request

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Certificate Request handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque certificate_request_context<0..2^8-1>;
    ///     Extension extensions<2..2^16-1>;
    /// } CertificateRequest;
    /// ```
    public struct CertificateRequest: Sendable, Hashable {
        /// `certificate_request_context` (zero length in the main handshake).
        public let certificateRequestContext: [Byte]

        /// `extensions` describing the certificate being requested.
        public let extensions: [RFC_8446.Extension.Data]

        /// Creates a CertificateRequest payload.
        ///
        /// - Throws: `Error.invalidContextLength` if the context exceeds 255
        ///   bytes; `Error.extensionsTooLong` if the serialized extensions
        ///   block exceeds the `uint16` bound (65535 bytes).
        public init(
            certificateRequestContext: [Byte] = [],
            extensions: [RFC_8446.Extension.Data]
        ) throws(Error) {
            guard certificateRequestContext.count <= 0xFF else {
                throw Error.invalidContextLength(certificateRequestContext.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.certificateRequestContext = certificateRequestContext
            self.extensions = extensions
        }

        /// Creates a CertificateRequest payload WITHOUT validation (parse path).
        init(__unchecked: Void, certificateRequestContext: [Byte], extensions: [RFC_8446.Extension.Data]) {
            self.certificateRequestContext = certificateRequestContext
            self.extensions = extensions
        }

        /// The handshake message type for this payload (`certificate_request`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .certificateRequest

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.CertificateRequest: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ request: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector8(request.certificateRequestContext, into: &buffer)
        RFC_8446.Wire.appendExtensions(request.extensions, into: &buffer)
    }

    /// Parses a CertificateRequest payload body (without the handshake header).
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let context = try reader.vector8()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(__unchecked: (), certificateRequestContext: context, extensions: extensions)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
