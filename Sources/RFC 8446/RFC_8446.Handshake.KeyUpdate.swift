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

// RFC_8446.Handshake.KeyUpdate.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.6.3: Key and Initialization Vector Update

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Key Update handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     KeyUpdateRequest request_update;
    /// } KeyUpdate;
    /// ```
    public struct KeyUpdate: Sendable, Hashable {
        /// Whether the recipient should respond with its own KeyUpdate.
        public let requestUpdate: Request

        /// Creates a KeyUpdate payload.
        public init(requestUpdate: Request) {
            self.requestUpdate = requestUpdate
        }

        /// The handshake message type for this payload (`key_update`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .keyUpdate

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.KeyUpdate: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ update: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(update.requestUpdate.rawValue))
    }

    /// Parses a KeyUpdate payload body (without the handshake header).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        let raw: UInt8
        do {
            raw = try reader.byte()
        } catch {
            throw .truncated
        }
        guard reader.isAtEnd else { throw .trailingData(reader.remaining) }
        self.init(requestUpdate: Request(rawValue: raw))
    }
}
