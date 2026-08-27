public import Binary_Serializable

extension RFC_8446.Extension.KeyShare {

    public struct ServerHello: Sendable, Hashable {

        public let serverShare: Entry

        public init(serverShare: Entry) {
            self.serverShare = serverShare
        }

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.KeyShare.extensionType,
                data: self.bytes
            )
        }
    }
}

extension RFC_8446.Extension.KeyShare.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Extension.KeyShare.Entry.serialize(value.serverShare, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.KeyShare.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let entry = try reader.keyShareEntry()
            try reader.expectEnd()
            self.init(serverShare: entry)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
