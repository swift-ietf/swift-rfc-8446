public import Binary_Serializable

extension RFC_8446 {

    public enum Handshake {}
}

extension RFC_8446.Handshake {

    public struct MessageType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let clientHello = Self(__unchecked: (), rawValue: 1)

        public static let serverHello = Self(__unchecked: (), rawValue: 2)

        public static let newSessionTicket = Self(__unchecked: (), rawValue: 4)

        public static let endOfEarlyData = Self(__unchecked: (), rawValue: 5)

        public static let encryptedExtensions = Self(__unchecked: (), rawValue: 8)

        public static let certificate = Self(__unchecked: (), rawValue: 11)

        public static let certificateRequest = Self(__unchecked: (), rawValue: 13)

        public static let certificateVerify = Self(__unchecked: (), rawValue: 15)

        public static let finished = Self(__unchecked: (), rawValue: 20)

        public static let keyUpdate = Self(__unchecked: (), rawValue: 24)

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

extension RFC_8446.Handshake {

    public struct Message: Sendable, Hashable {

        public let type: MessageType

        public let body: [Byte]

        public init(type: MessageType, body: [Byte]) throws(Error) {
            guard body.count <= 0xFF_FFFF else {
                throw Error.bodyTooLong(body.count)
            }
            self.type = type
            self.body = body
        }

        init(__unchecked: Void, type: MessageType, body: [Byte]) {
            self.type = type
            self.body = body
        }

    }
}

extension RFC_8446.Handshake.Message: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ message: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(Byte(message.type.rawValue))

        let length = message.body.count
        buffer.append(Byte(UInt8((length >> 16) & 0xFF)))
        buffer.append(Byte(UInt8((length >> 8) & 0xFF)))
        buffer.append(Byte(UInt8(length & 0xFF)))

        buffer.append(contentsOf: message.body)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        let rawType: UInt8
        let length: Int
        do {
            rawType = try reader.byte()
            length = try reader.uint24()
        } catch {
            throw .truncated
        }
        guard reader.remaining == length else {
            throw .lengthMismatch(length, reader.remaining)
        }
        let body: [Byte]
        do {
            body = try reader.take(length)
        } catch {
            throw .truncated
        }

        self.init(
            __unchecked: (),
            type: RFC_8446.Handshake.MessageType(rawValue: rawType),
            body: body
        )
    }
}
