public import Binary_Serializable_Primitives

extension RFC_8446.Extension.SupportedVersions {

    public struct ClientHello: Sendable, Hashable {

        public let versions: [RFC_8446.ProtocolVersion]

        public init(
            versions: [RFC_8446.ProtocolVersion]
        ) throws(RFC_8446.Extension.SupportedVersions.Error) {
            guard (1...127).contains(versions.count) else {
                throw .invalidVersionCount(versions.count)
            }
            self.versions = versions
        }

        init(__unchecked: Void, versions: [RFC_8446.ProtocolVersion]) {
            self.versions = versions
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

extension RFC_8446.Extension.SupportedVersions.ClientHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for version in value.versions {
            block.append(contentsOf: version.rawValue.bytes(endianness: .big))
        }
        RFC_8446.Wire.appendVector8(block, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.SupportedVersions.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector8()
            var sub = RFC_8446.Wire.Reader(block)
            var versions: [RFC_8446.ProtocolVersion] = []
            while !sub.isAtEnd {
                versions.append(RFC_8446.ProtocolVersion(rawValue: try sub.uint16()))
            }
            try reader.expectEnd()
            self.init(__unchecked: (), versions: versions)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
