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

// RFC_8446.Handshake.NewSessionTicket.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.6.1: New Session Ticket Message

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {
    /// New Session Ticket handshake payload.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     uint32 ticket_lifetime;
    ///     uint32 ticket_age_add;
    ///     opaque ticket_nonce<0..255>;
    ///     opaque ticket<1..2^16-1>;
    ///     Extension extensions<0..2^16-2>;
    /// } NewSessionTicket;
    /// ```
    public struct NewSessionTicket: Sendable, Hashable {
        /// `ticket_lifetime` in seconds.
        public let ticketLifetime: UInt32

        /// `ticket_age_add`, obscuring the transmitted ticket age.
        public let ticketAgeAdd: UInt32

        /// `ticket_nonce`, unique per ticket on a connection.
        public let ticketNonce: [Byte]

        /// `ticket`, the opaque PSK identity label.
        public let ticket: [Byte]

        /// `extensions` for the ticket (e.g. `early_data`).
        public let extensions: [RFC_8446.Extension.Data]

        /// Creates a NewSessionTicket payload.
        ///
        /// - Throws: `Error.invalidNonceLength` if the nonce exceeds 255
        ///   bytes; `Error.invalidTicketLength` if the ticket is outside
        ///   1...65535 bytes; `Error.extensionsTooLong` if the serialized
        ///   extensions block exceeds 65534 bytes.
        public init(
            ticketLifetime: UInt32,
            ticketAgeAdd: UInt32,
            ticketNonce: [Byte],
            ticket: [Byte],
            extensions: [RFC_8446.Extension.Data] = []
        ) throws(Error) {
            guard ticketNonce.count <= 0xFF else {
                throw Error.invalidNonceLength(ticketNonce.count)
            }
            guard (1...0xFFFF).contains(ticket.count) else {
                throw Error.invalidTicketLength(ticket.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFE else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.ticketLifetime = ticketLifetime
            self.ticketAgeAdd = ticketAgeAdd
            self.ticketNonce = ticketNonce
            self.ticket = ticket
            self.extensions = extensions
        }

        /// Creates a NewSessionTicket payload WITHOUT validation (parse path).
        init(
            __unchecked: Void,
            ticketLifetime: UInt32,
            ticketAgeAdd: UInt32,
            ticketNonce: [Byte],
            ticket: [Byte],
            extensions: [RFC_8446.Extension.Data]
        ) {
            self.ticketLifetime = ticketLifetime
            self.ticketAgeAdd = ticketAgeAdd
            self.ticketNonce = ticketNonce
            self.ticket = ticket
            self.extensions = extensions
        }

        /// The handshake message type for this payload (`new_session_ticket`).
        public static let handshakeType: RFC_8446.Handshake.MessageType = .newSessionTicket

        /// Wraps this payload in a ``RFC_8446/Handshake/Message`` envelope.
        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.NewSessionTicket: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ ticket: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: ticket.ticketLifetime.bytes(endianness: .big))
        buffer.append(contentsOf: ticket.ticketAgeAdd.bytes(endianness: .big))
        RFC_8446.Wire.appendVector8(ticket.ticketNonce, into: &buffer)
        RFC_8446.Wire.appendVector16(ticket.ticket, into: &buffer)
        RFC_8446.Wire.appendExtensions(ticket.extensions, into: &buffer)
    }

    /// Parses a NewSessionTicket payload body (without the handshake header).
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let lifetime = try reader.uint32()
            let ageAdd = try reader.uint32()
            let nonce = try reader.vector8()
            let ticket = try reader.vector16()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                ticketLifetime: lifetime,
                ticketAgeAdd: ageAdd,
                ticketNonce: nonce,
                ticket: ticket,
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
