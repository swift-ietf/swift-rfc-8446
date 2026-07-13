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

// RFC_8446.Handshake.ClientHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.1.2: Client Hello

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Client Hello handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// uint16 ProtocolVersion;
    /// opaque Random[32];
    /// uint8 CipherSuite[2];
    ///
    /// struct {
    ///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    ///     Random random;
    ///     opaque legacy_session_id<0..32>;
    ///     CipherSuite cipher_suites<2..2^16-2>;
    ///     opaque legacy_compression_methods<1..2^8-1>;
    ///     Extension extensions<8..2^16-1>;
    /// } ClientHello;
    /// ```
    ///
    /// In TLS 1.3 `legacy_version` is frozen at 0x0303 and the true version
    /// preference travels in the `supported_versions` extension.
    public struct ClientHello: Sendable, Hashable {
        /// `legacy_version`, frozen at 0x0303 (TLS 1.2) in TLS 1.3.
        public let legacyVersion: RFC_8446.ProtocolVersion

        /// 32-byte `random` value (opaque byte-domain).
        public let random: [Byte]

        /// `legacy_session_id` (opaque byte-domain; 0...32 bytes).
        public let legacySessionID: [Byte]

        /// `cipher_suites` in descending order of client preference.
        public let cipherSuites: [RFC_8446.CipherSuite]

        /// `legacy_compression_methods` (exactly `[0]` for TLS 1.3).
        public let legacyCompressionMethods: [Byte]

        /// `extensions` in the order sent.
        public let extensions: [RFC_8446.Extension.Data]

        /// Creates a ClientHello payload.
        public init(
            legacyVersion: RFC_8446.ProtocolVersion = .legacy,
            random: [Byte],
            legacySessionID: [Byte] = [],
            cipherSuites: [RFC_8446.CipherSuite],
            legacyCompressionMethods: [Byte] = [Byte(0)],
            extensions: [RFC_8446.Extension.Data]
        ) {
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionID = legacySessionID
            self.cipherSuites = cipherSuites
            self.legacyCompressionMethods = legacyCompressionMethods
            self.extensions = extensions
        }

        /// The handshake message type for this payload (`client_hello`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .clientHello

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.ClientHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ hello: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: hello.legacyVersion.rawValue.bytes(endianness: .big))
        buffer.append(contentsOf: hello.random)
        RFC_8446.Wire.appendVector8(hello.legacySessionID, into: &buffer)
        RFC_8446.Wire.appendUInt16List(hello.cipherSuites.map(\.rawValue), into: &buffer)
        RFC_8446.Wire.appendVector8(hello.legacyCompressionMethods, into: &buffer)
        RFC_8446.Wire.appendExtensions(hello.extensions, into: &buffer)
    }

    /// Parses a ClientHello payload body (without the handshake header).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let version = try reader.uint16()
            let random = try reader.take(32)
            let sessionID = try reader.vector8()
            let suites = try reader.uint16List()
            let compression = try reader.vector8()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(
                legacyVersion: RFC_8446.ProtocolVersion(rawValue: version),
                random: random,
                legacySessionID: sessionID,
                cipherSuites: suites.map(RFC_8446.CipherSuite.init(rawValue:)),
                legacyCompressionMethods: compression,
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
