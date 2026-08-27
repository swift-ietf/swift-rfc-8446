public import Binary_Serializable

extension RFC_8446.Handshake {

    public struct NewSessionTicket: Sendable, Hashable {

        public let ticketLifetime: UInt32

        public let ticketAgeAdd: UInt32

        public let ticketNonce: [Byte]

        public let ticket: [Byte]

        public let extensions: [RFC_8446.Extension.Data]

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

        public static let handshakeType: RFC_8446.Handshake.MessageType = .newSessionTicket

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

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
