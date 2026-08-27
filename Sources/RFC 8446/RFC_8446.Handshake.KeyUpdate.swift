public import Binary_Serializable

extension RFC_8446.Handshake {

    public struct KeyUpdate: Sendable, Hashable {

        public let requestUpdate: Request

        public init(requestUpdate: Request) {
            self.requestUpdate = requestUpdate
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .keyUpdate

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.KeyUpdate: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ update: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(update.requestUpdate.rawValue))
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
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
