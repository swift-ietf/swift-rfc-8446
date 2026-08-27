public import Binary_Serializable

extension RFC_8446.Extension.KeyShare {

    public struct HelloRetryRequest: Sendable, Hashable {

        public let selectedGroup: RFC_8446.Extension.NamedGroup

        public init(selectedGroup: RFC_8446.Extension.NamedGroup) {
            self.selectedGroup = selectedGroup
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

extension RFC_8446.Extension.KeyShare.HelloRetryRequest: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.selectedGroup.rawValue.bytes(endianness: .big))
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.KeyShare.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let group = try reader.uint16()
            try reader.expectEnd()
            self.init(selectedGroup: RFC_8446.Extension.NamedGroup(rawValue: group))
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
