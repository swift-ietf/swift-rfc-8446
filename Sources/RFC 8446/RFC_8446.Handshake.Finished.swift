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

// RFC_8446.Handshake.Finished.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.4: Finished

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// Finished handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque verify_data[Hash.length];
    /// } Finished;
    /// ```
    ///
    /// `verify_data` occupies the entire message body — there is no length
    /// prefix; its length is `Hash.length` for the negotiated cipher suite.
    /// The value itself is
    /// `HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*,
    /// CertificateVerify*))`; see ``RFC_8446/KeySchedule`` for the derivation
    /// shapes.
    public struct Finished: Sendable, Hashable {
        /// The `verify_data` bytes (opaque byte-domain, `Hash.length` long).
        public let verifyData: [Byte]

        /// Creates a Finished payload.
        ///
        /// - Throws: `Error.verifyDataTooLong` if `verify_data` exceeds the
        ///   handshake body's `uint24` bound (2^24-1 bytes). The exact
        ///   `Hash.length` is negotiated and can only be checked by the caller.
        public init(verifyData: [Byte]) throws(Error) {
            guard verifyData.count <= 0xFF_FFFF else {
                throw Error.verifyDataTooLong(verifyData.count)
            }
            self.verifyData = verifyData
        }

        /// Creates a Finished payload WITHOUT validation (parse path).
        init(__unchecked: Void, verifyData: [Byte]) {
            self.verifyData = verifyData
        }

        /// The handshake message type for this payload (`finished`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .finished

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.Finished: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ finished: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: finished.verifyData)
    }

    /// Parses a Finished payload body (without the handshake header).
    ///
    /// The whole input is taken as `verify_data`; its length is `Hash.length`
    /// for the negotiated cipher suite and can only be validated by the caller,
    /// so parsing itself has no failure mode (hence non-throwing).
    public init<Bytes: Collection>(binary bytes: Bytes) where Bytes.Element == Byte {
        self.init(__unchecked: (), verifyData: Array(bytes))
    }
}
