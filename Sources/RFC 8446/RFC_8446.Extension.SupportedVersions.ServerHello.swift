public import Binary_Serializable

extension RFC_8446.Extension.SupportedVersions {

    public struct ServerHello: Sendable, Hashable {

        public let selectedVersion: RFC_8446.ProtocolVersion

        public init(selectedVersion: RFC_8446.ProtocolVersion) {
            self.selectedVersion = selectedVersion
        }

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.SupportedVersions.extensionType,
                data: self.bytes
            )
        }
    }
}

extension RFC_8446.Extension.SupportedVersions.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.selectedVersion.rawValue.bytes(endianness: .big))
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.SupportedVersions.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let version = try reader.uint16()
            try reader.expectEnd()
            self.init(selectedVersion: RFC_8446.ProtocolVersion(rawValue: version))
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
