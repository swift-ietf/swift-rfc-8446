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

// RFC_8446.Handshake.swift
// swift-rfc-8446
//
// RFC 8446 Section 4: Handshake Protocol

extension RFC_8446 {
    /// Handshake Protocol namespace
    ///
    /// The handshake protocol negotiates the TLS version, cipher suite,
    /// and other parameters, and authenticates the server (and optionally
    /// the client).
    ///
    /// ## TLS 1.3 Handshake
    ///
    /// ```
    /// Client                                           Server
    ///
    /// Key  ^ ClientHello
    /// Exch | + key_share*
    ///      | + signature_algorithms*
    ///      | + psk_key_exchange_modes*
    ///      v + pre_shared_key*         -------->
    ///                                                 ServerHello  ^ Key
    ///                                                + key_share*  | Exch
    ///                                           + pre_shared_key*  v
    ///                                       {EncryptedExtensions}  ^  Server
    ///                                       {CertificateRequest*}  v  Params
    ///                                              {Certificate*}  ^
    ///                                        {CertificateVerify*}  | Auth
    ///                                                  {Finished}  v
    ///                               <--------  [Application Data*]
    ///      ^ {Certificate*}
    /// Auth | {CertificateVerify*}
    ///      v {Finished}              -------->
    ///        [Application Data]      <------->  [Application Data]
    /// ```
    public enum Handshake {}
}

// MARK: - Handshake Type

extension RFC_8446.Handshake {
    /// Handshake Message Type
    ///
    /// Identifies the type of handshake message.
    public struct MessageType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a MessageType WITHOUT validation
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// client_hello (1)
        public static let clientHello = Self(__unchecked: (), rawValue: 1)

        /// server_hello (2)
        public static let serverHello = Self(__unchecked: (), rawValue: 2)

        /// new_session_ticket (4)
        public static let newSessionTicket = Self(__unchecked: (), rawValue: 4)

        /// end_of_early_data (5)
        public static let endOfEarlyData = Self(__unchecked: (), rawValue: 5)

        /// encrypted_extensions (8)
        public static let encryptedExtensions = Self(__unchecked: (), rawValue: 8)

        /// certificate (11)
        public static let certificate = Self(__unchecked: (), rawValue: 11)

        /// certificate_request (13)
        public static let certificateRequest = Self(__unchecked: (), rawValue: 13)

        /// certificate_verify (15)
        public static let certificateVerify = Self(__unchecked: (), rawValue: 15)

        /// finished (20)
        public static let finished = Self(__unchecked: (), rawValue: 20)

        /// key_update (24)
        public static let keyUpdate = Self(__unchecked: (), rawValue: 24)

        /// message_hash (254)
        public static let messageHash = Self(__unchecked: (), rawValue: 254)
    }
}

extension RFC_8446.Handshake.MessageType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 1: return "client_hello"
        case 2: return "server_hello"
        case 4: return "new_session_ticket"
        case 5: return "end_of_early_data"
        case 8: return "encrypted_extensions"
        case 11: return "certificate"
        case 13: return "certificate_request"
        case 15: return "certificate_verify"
        case 20: return "finished"
        case 24: return "key_update"
        case 254: return "message_hash"
        default: return "handshake(\(rawValue))"
        }
    }
}

// MARK: - Handshake Message

extension RFC_8446.Handshake {
    /// Generic Handshake Message
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     HandshakeType msg_type;    /* 1 byte */
    ///     uint24 length;             /* 3 bytes */
    ///     select (Handshake.msg_type) {
    ///         case client_hello:          ClientHello;
    ///         case server_hello:          ServerHello;
    ///         ...
    ///     };
    /// } Handshake;
    /// ```
    public struct Message: Sendable, Hashable {
        /// Message type
        public let type: MessageType

        /// Message body (opaque byte-domain payload)
        public let body: [Byte]

        /// Creates a handshake message
        public init(type: MessageType, body: [Byte]) {
            self.type = type
            self.body = body
        }

        /// Stdlib-interop forwarder: construction from `[UInt8]` body.
        @_disfavoredOverload
        public init(type: MessageType, body: [UInt8]) {
            self.init(type: type, body: [Byte](body))
        }
    }
}

extension RFC_8446.Handshake.Message: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ message: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // Type (MessageType.rawValue stays UInt8 in separate file scope;
        // bridge via Byte()).
        buffer.append(Byte(message.type.rawValue))

        // Length (3 bytes, uint24). Manual byte split since BinaryInteger
        // doesn't have a 3-byte form; arithmetic-domain Int internal, Byte()
        // bridge at append boundary.
        let length = message.body.count
        buffer.append(Byte(UInt8((length >> 16) & 0xFF)))
        buffer.append(Byte(UInt8((length >> 8) & 0xFF)))
        buffer.append(Byte(UInt8(length & 0xFF)))

        // Body (opaque byte-domain payload, already [Byte])
        buffer.append(contentsOf: message.body)
    }
}
