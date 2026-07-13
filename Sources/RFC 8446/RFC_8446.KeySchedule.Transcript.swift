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

// RFC_8446.KeySchedule.Transcript.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.1: The Transcript Hash

public import Binary_Serializable_Primitives

extension RFC_8446.KeySchedule {
    /// Accumulates handshake-message bytes for the transcript hash.
    ///
    /// Per RFC 8446 Section 4.4.1, the transcript is the concatenation of the
    /// indicated handshake messages, *including* each message's type and length
    /// fields but not the record-layer headers. Append full
    /// ``RFC_8446/Handshake/Message`` envelopes (or their raw bytes), then hash
    /// at any point via a ``Witness``.
    public struct Transcript: Sendable, Hashable {
        /// The accumulated handshake-message bytes.
        public private(set) var messages: [Byte]

        /// Creates an empty transcript.
        public init() {
            self.messages = []
        }

        /// Creates a transcript seeded with existing message bytes.
        public init(messages: [Byte]) {
            self.messages = messages
        }

        /// Appends raw handshake-message bytes (type + length + body).
        public mutating func append(_ bytes: [Byte]) {
            messages.append(contentsOf: bytes)
        }

        /// Appends a serialized handshake message envelope.
        public mutating func append(_ message: RFC_8446.Handshake.Message) {
            messages.append(contentsOf: message.bytes)
        }

        /// `Transcript-Hash(messages)` computed via the witness's hash.
        public func hash(using witness: RFC_8446.KeySchedule.Witness) -> [Byte] {
            witness.hash(messages)
        }
    }
}
