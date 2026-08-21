public import Binary_Serializable_Primitives

extension RFC_8446.Extension.EarlyData {

    public struct Ticket: Sendable, Hashable {

        public let maxEarlyDataSize: UInt32

        public init(maxEarlyDataSize: UInt32) {
            self.maxEarlyDataSize = maxEarlyDataSize
        }

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.EarlyData.extensionType,
                data: self.bytes
            )
        }
    }
}

extension RFC_8446.Extension.EarlyData.Ticket: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.maxEarlyDataSize.bytes(endianness: .big))
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.EarlyData.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let size = try reader.uint32()
            try reader.expectEnd()
            self.init(maxEarlyDataSize: size)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
