public import Binary_Serializable_Primitives

extension RFC_8446.Extension {

    public struct Padding: Sendable, Hashable {

        public let padding: [Byte]

        public init(padding: [Byte]) throws(Error) {
            guard padding.count <= 0xFFFF else {
                throw Error.invalidPaddingLength(padding.count)
            }
            self.padding = padding
        }

        public init(length: Int) throws(Error) {
            guard (0...0xFFFF).contains(length) else {
                throw Error.invalidPaddingLength(length)
            }
            self.padding = Array(repeating: Byte(0), count: length)
        }

        init(__unchecked: Void, padding: [Byte]) {
            self.padding = padding
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .padding

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.Padding: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.padding)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        let padding = Array(bytes)
        guard padding.count <= 0xFFFF else {
            throw Error.invalidPaddingLength(padding.count)
        }
        self.init(__unchecked: (), padding: padding)
    }
}
