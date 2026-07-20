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

// RFC_8446.Handshake.ServerHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.1.3: Server Hello / Section 4.1.4: Hello Retry Request

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Server Hello handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    ///     Random random;
    ///     opaque legacy_session_id_echo<0..32>;
    ///     CipherSuite cipher_suite;
    ///     uint8 legacy_compression_method = 0;
    ///     Extension extensions<6..2^16-1>;
    /// } ServerHello;
    /// ```
    ///
    /// The HelloRetryRequest message (Section 4.1.4) uses the identical
    /// structure but sets ``random`` to the special value
    /// ``helloRetryRequestRandom`` (the SHA-256 of `"HelloRetryRequest"`).
    /// Discriminate with ``isHelloRetryRequest``.
    public struct ServerHello: Sendable, Hashable {
        /// `legacy_version`, frozen at 0x0303 (TLS 1.2) in TLS 1.3.
        public let legacyVersion: RFC_8446.ProtocolVersion

        /// 32-byte `random` value (opaque byte-domain).
        public let random: [Byte]

        /// `legacy_session_id_echo` (opaque byte-domain; 0...32 bytes).
        public let legacySessionIDEcho: [Byte]

        /// The single `cipher_suite` selected by the server.
        public let cipherSuite: RFC_8446.CipherSuite

        /// `legacy_compression_method`, which MUST be 0.
        public let legacyCompressionMethod: UInt8

        /// `extensions` in the order sent.
        public let extensions: [RFC_8446.Extension.Data]

        /// Creates a ServerHello payload.
        ///
        /// - Throws: `Error` if any field violates its spec length bounds:
        ///   32-byte `random`, `legacy_session_id_echo` up to 32 bytes, and a
        ///   serialized extensions block of at most 65535 bytes.
        public init(
            legacyVersion: RFC_8446.ProtocolVersion = .legacy,
            random: [Byte],
            legacySessionIDEcho: [Byte] = [],
            cipherSuite: RFC_8446.CipherSuite,
            legacyCompressionMethod: UInt8 = 0,
            extensions: [RFC_8446.Extension.Data]
        ) throws(Error) {
            guard random.count == 32 else {
                throw Error.invalidRandomLength(random.count)
            }
            guard legacySessionIDEcho.count <= 32 else {
                throw Error.invalidSessionIDEchoLength(legacySessionIDEcho.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionIDEcho = legacySessionIDEcho
            self.cipherSuite = cipherSuite
            self.legacyCompressionMethod = legacyCompressionMethod
            self.extensions = extensions
        }

        /// Creates a ServerHello payload WITHOUT validation (parse path).
        init(
            __unchecked: Void,
            legacyVersion: RFC_8446.ProtocolVersion,
            random: [Byte],
            legacySessionIDEcho: [Byte],
            cipherSuite: RFC_8446.CipherSuite,
            legacyCompressionMethod: UInt8,
            extensions: [RFC_8446.Extension.Data]
        ) {
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionIDEcho = legacySessionIDEcho
            self.cipherSuite = cipherSuite
            self.legacyCompressionMethod = legacyCompressionMethod
            self.extensions = extensions
        }

        /// The special `random` value marking a HelloRetryRequest.
        ///
        /// Per RFC 8446 Section 4.1.3, this is the SHA-256 of the ASCII string
        /// `"HelloRetryRequest"`:
        ///
        /// ```
        /// CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
        /// C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
        /// ```
        public static let helloRetryRequestRandom: [Byte] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ]

        /// Whether this message is actually a HelloRetryRequest, identified by
        /// ``random`` matching ``helloRetryRequestRandom``.
        public var isHelloRetryRequest: Bool {
            random == Self.helloRetryRequestRandom
        }

        /// The handshake message type for this payload (`server_hello`).
        ///
        /// HelloRetryRequest also uses `server_hello` on the wire (Section
        /// 4.1.4); the distinction is carried entirely by ``random``.
        public static let handshakeType: RFC_8446.Handshake.MessageType = .serverHello

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ hello: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: hello.legacyVersion.rawValue.bytes(endianness: .big))
        buffer.append(contentsOf: hello.random)
        RFC_8446.Wire.appendVector8(hello.legacySessionIDEcho, into: &buffer)
        buffer.append(contentsOf: hello.cipherSuite.rawValue.bytes(endianness: .big))
        buffer.append(Byte(hello.legacyCompressionMethod))
        RFC_8446.Wire.appendExtensions(hello.extensions, into: &buffer)
    }

    /// Parses a ServerHello payload body (without the handshake header).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let version = try reader.uint16()
            let random = try reader.take(32)
            let sessionID = try reader.vector8()
            let suite = try reader.uint16()
            let compression = try reader.byte()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                legacyVersion: RFC_8446.ProtocolVersion(rawValue: version),
                random: random,
                legacySessionIDEcho: sessionID,
                cipherSuite: RFC_8446.CipherSuite(rawValue: suite),
                legacyCompressionMethod: compression,
                extensions: extensions
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
