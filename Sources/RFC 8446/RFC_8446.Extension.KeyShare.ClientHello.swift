public import Binary_Serializable

extension RFC_8446.Extension.KeyShare {

    public struct ClientHello: Sendable, Hashable {

        public let clientShares: [Entry]

        public init(clientShares: [Entry]) throws(RFC_8446.Extension.KeyShare.Error) {
            let blockLength = clientShares.reduce(0) { $0 + 4 + $1.keyExchange.count }
            guard blockLength <= 0xFFFD else {
                throw .clientSharesTooLong(blockLength)
            }
            self.clientShares = clientShares
        }

        init(__unchecked: Void, clientShares: [Entry]) {
            self.clientShares = clientShares
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

extension RFC_8446.Extension.KeyShare.ClientHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for entry in value.clientShares {
            RFC_8446.Extension.KeyShare.Entry.serialize(entry, into: &block)
        }
        RFC_8446.Wire.appendVector16(block, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.KeyShare.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var entries: [RFC_8446.Extension.KeyShare.Entry] = []
            while !sub.isAtEnd {
                entries.append(try sub.keyShareEntry())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), clientShares: entries)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
