public import Binary_Serializable_Primitives

extension RFC_8446.Extension.KeyShare {

    public struct Entry: Sendable, Hashable {

        public let group: RFC_8446.Extension.NamedGroup

        public let keyExchange: [Byte]

        public init(
            group: RFC_8446.Extension.NamedGroup,
            keyExchange: [Byte]
        ) throws(RFC_8446.Extension.KeyShare.Error) {
            guard (1...0xFFFB).contains(keyExchange.count) else {
                throw .invalidKeyExchangeLength(keyExchange.count)
            }
            self.group = group
            self.keyExchange = keyExchange
        }

        init(__unchecked: Void, group: RFC_8446.Extension.NamedGroup, keyExchange: [Byte]) {
            self.group = group
            self.keyExchange = keyExchange
        }
    }
}

extension RFC_8446.Extension.KeyShare.Entry: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ entry: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: entry.group.rawValue.bytes(endianness: .big))
        RFC_8446.Wire.appendVector16(entry.keyExchange, into: &buffer)
    }
}

extension RFC_8446.Wire.Reader {

    mutating func keyShareEntry() throws(RFC_8446.Wire.Error) -> RFC_8446.Extension.KeyShare.Entry {
        let group = try uint16()
        let keyExchange = try vector16()
        return RFC_8446.Extension.KeyShare.Entry(
            __unchecked: (),
            group: RFC_8446.Extension.NamedGroup(rawValue: group),
            keyExchange: keyExchange
        )
    }
}
