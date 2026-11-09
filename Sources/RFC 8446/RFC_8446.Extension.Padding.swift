public import Binary

extension RFC_8446.Extension {

    public struct Padding: Sendable, Hashable {

        public let padding: [Byte]

        public init(padding: [Byte]) throws(Error) {
            guard padding.count <= 0xFFFF else {
                throw Error.invalidPaddingLength(padding.count)
            }
            if let offset = padding.firstIndex(where: { $0 != Byte(0) }) {
                throw Error.nonZeroByte(offset)
            }
            self.padding = padding
        }

        public init(length: Int) throws(Error) {
            guard (0...0xFFFF).contains(length) else {
                throw Error.invalidPaddingLength(length)
            }
            self.padding = Array(repeating: Byte(0), count: length)
        }

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.Padding {
    public static let extensionType: RFC_8446.Extension.ExtensionType = .padding
}

extension RFC_8446.Extension.Padding: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.padding)
    }

    public init<Bytes: Swift::Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        try self.init(padding: Array(bytes))
    }
}
