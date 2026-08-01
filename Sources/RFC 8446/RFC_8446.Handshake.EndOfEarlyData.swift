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

// RFC_8446.Handshake.EndOfEarlyData.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.5: End of Early Data

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// End of Early Data handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {} EndOfEarlyData;
    /// ```
    ///
    /// The body is empty; it signals that all 0-RTT application data has been
    /// transmitted and following records use handshake traffic keys.
    public struct EndOfEarlyData: Sendable, Hashable {
        /// Creates an EndOfEarlyData payload.
        public init() {}

        /// The handshake message type for this payload (`end_of_early_data`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .endOfEarlyData

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: [])
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.EndOfEarlyData: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // EndOfEarlyData has an empty body — nothing to append.
    }

    /// Parses an EndOfEarlyData payload body (which MUST be empty).
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else { throw .trailingData(bytes.count) }
        self.init()
    }
}
