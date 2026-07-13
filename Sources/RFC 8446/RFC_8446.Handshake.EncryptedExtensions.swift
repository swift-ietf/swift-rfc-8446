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

// RFC_8446.Handshake.EncryptedExtensions.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.3.1: Encrypted Extensions

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Encrypted Extensions handshake payload.
    ///
    /// The first message encrypted under the server handshake traffic secret;
    /// carries extensions not needed to establish the cryptographic context.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     Extension extensions<0..2^16-1>;
    /// } EncryptedExtensions;
    /// ```
    public struct EncryptedExtensions: Sendable, Hashable {
        /// `extensions` in the order sent.
        public let extensions: [RFC_8446.Extension.Data]

        /// Creates an EncryptedExtensions payload.
        public init(extensions: [RFC_8446.Extension.Data]) {
            self.extensions = extensions
        }

        /// The handshake message type for this payload (`encrypted_extensions`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .encryptedExtensions

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.EncryptedExtensions: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendExtensions(value.extensions, into: &buffer)
    }

    /// Parses an EncryptedExtensions payload body (without the handshake header).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(extensions: extensions)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
