public import Binary_Serializable

extension RFC_8446.Handshake {

    public struct EndOfEarlyData: Sendable, Hashable {

        public init() {}

        public static let handshakeType: RFC_8446.Handshake.MessageType = .endOfEarlyData

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: [])
        }
    }
}

extension RFC_8446.Handshake.EndOfEarlyData: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else { throw .trailingData(bytes.count) }
        self.init()
    }
}
