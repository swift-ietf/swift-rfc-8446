public import Binary_Serializable

extension RFC_8446.Extension.PreSharedKey {

    public struct ServerHello: Sendable, Hashable {

        public let selectedIdentity: UInt16

        public init(selectedIdentity: UInt16) {
            self.selectedIdentity = selectedIdentity
        }

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.PreSharedKey.extensionType,
                data: self.bytes
            )
        }
    }
}

extension RFC_8446.Extension.PreSharedKey.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.selectedIdentity.bytes(endianness: .big))
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.PreSharedKey.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let index = try reader.uint16()
            try reader.expectEnd()
            self.init(selectedIdentity: index)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
