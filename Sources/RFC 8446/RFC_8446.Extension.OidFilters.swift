public import Binary_Serializable_Primitives

extension RFC_8446.Extension {

    public struct OidFilters: Sendable, Hashable {

        public let filters: [Filter]

        public init(filters: [Filter]) throws(Error) {
            let blockLength = filters.reduce(0) {
                $0 + 1 + $1.certificateExtensionOID.count + 2 + $1.certificateExtensionValues.count
            }
            guard blockLength <= 0xFFFD else {
                throw Error.filtersTooLong(blockLength)
            }
            self.filters = filters
        }

        init(__unchecked: Void, filters: [Filter]) {
            self.filters = filters
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .oidFilters

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.OidFilters: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for filter in value.filters {
            Filter.serialize(filter, into: &block)
        }
        RFC_8446.Wire.appendVector16(block, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var filters: [Filter] = []
            while !sub.isAtEnd {
                filters.append(try sub.oidFilter())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), filters: filters)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
