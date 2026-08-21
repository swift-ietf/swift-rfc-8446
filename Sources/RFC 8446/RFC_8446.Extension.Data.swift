public import Binary_Serializable_Primitives

extension RFC_8446.Extension {

    public struct Data: Sendable, Hashable {

        public let type: ExtensionType

        public let data: [Byte]

        public init(type: ExtensionType, data: [Byte]) throws(Error) {
            guard data.count <= 0xFFFF else {
                throw Error.dataTooLong(data.count)
            }
            self.type = type
            self.data = data
        }

        init(__unchecked: Void, type: ExtensionType, data: [Byte]) {
            self.type = type
            self.data = data
        }

    }
}

extension RFC_8446.Extension.Data: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ ext: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(contentsOf: ext.type.rawValue.bytes(endianness: .big))

        let length = UInt16(ext.data.count)
        buffer.append(contentsOf: length.bytes(endianness: .big))

        buffer.append(contentsOf: ext.data)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        let type: UInt16
        let data: [Byte]
        do {
            type = try reader.uint16()
            data = try reader.vector16()
        } catch {
            throw .truncated
        }
        guard reader.isAtEnd else { throw .trailingData(reader.remaining) }

        self.init(
            __unchecked: (),
            type: RFC_8446.Extension.ExtensionType(rawValue: type),
            data: data
        )
    }
}
