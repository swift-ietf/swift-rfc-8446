public import Binary_Serializable_Primitives

extension RFC_8446.KeySchedule {

    public struct HkdfLabel: Sendable, Hashable {

        public let length: UInt16

        public let label: [Byte]

        public let context: [Byte]

        public init(length: UInt16, label: [Byte], context: [Byte]) {
            self.length = length
            self.label = label
            self.context = context
        }

        public init(length: UInt16, label: some StringProtocol, context: [Byte]) {
            var full = Self.prefix
            full.append(contentsOf: label.utf8.map(Byte.init))
            self.init(length: length, label: full, context: context)
        }

        public static let prefix: [Byte] = Array("tls13 ".utf8).map(Byte.init)
    }
}

extension RFC_8446.KeySchedule.HkdfLabel: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.length.bytes(endianness: .big))
        RFC_8446.Wire.appendVector8(value.label, into: &buffer)
        RFC_8446.Wire.appendVector8(value.context, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let length = try reader.uint16()
            let label = try reader.vector8()
            let context = try reader.vector8()
            try reader.expectEnd()
            self.init(length: length, label: label, context: context)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
