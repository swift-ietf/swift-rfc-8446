public import Binary_Serializable

extension RFC_8446.Extension {

    public struct PostHandshakeAuth: Sendable, Hashable {

        public init() {}

        public static let extensionType: RFC_8446.Extension.ExtensionType = .postHandshakeAuth

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: [])
        }
    }
}

extension RFC_8446.Extension.PostHandshakeAuth: Binary.Serializable {
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
