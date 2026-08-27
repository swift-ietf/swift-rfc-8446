public import Binary_Serializable

extension RFC_8446.Extension.EarlyData {

    public struct Indication: Sendable, Hashable {

        public init() {}

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.EarlyData.extensionType,
                data: []
            )
        }
    }
}

extension RFC_8446.Extension.EarlyData.Indication: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.EarlyData.Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else { throw .trailingData(bytes.count) }
        self.init()
    }
}
