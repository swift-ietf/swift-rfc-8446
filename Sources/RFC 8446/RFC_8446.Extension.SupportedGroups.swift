public import Binary_Serializable

extension RFC_8446.Extension {

    public struct SupportedGroups: Sendable, Hashable {

        public let namedGroupList: [NamedGroup]

        public init(namedGroupList: [NamedGroup]) throws(Error) {
            guard (1...32766).contains(namedGroupList.count) else {
                throw Error.invalidGroupCount(namedGroupList.count)
            }
            self.namedGroupList = namedGroupList
        }

        init(__unchecked: Void, namedGroupList: [NamedGroup]) {
            self.namedGroupList = namedGroupList
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .supportedGroups

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.SupportedGroups: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendUInt16List(value.namedGroupList.map(\.rawValue), into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let values = try reader.uint16List()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                namedGroupList: values.map(RFC_8446.Extension.NamedGroup.init(rawValue:))
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
