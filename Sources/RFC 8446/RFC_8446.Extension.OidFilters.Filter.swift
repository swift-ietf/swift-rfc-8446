public import Binary_Serializable

extension RFC_8446.Extension.OidFilters {

    public struct Filter: Sendable, Hashable {

        public let certificateExtensionOID: [Byte]

        public let certificateExtensionValues: [Byte]

        public init(
            certificateExtensionOID: [Byte],
            certificateExtensionValues: [Byte]
        ) throws(RFC_8446.Extension.OidFilters.Error) {
            guard (1...0xFF).contains(certificateExtensionOID.count) else {
                throw .invalidOIDLength(certificateExtensionOID.count)
            }
            guard certificateExtensionValues.count <= 0xFFFF else {
                throw .valuesTooLong(certificateExtensionValues.count)
            }
            self.certificateExtensionOID = certificateExtensionOID
            self.certificateExtensionValues = certificateExtensionValues
        }

        init(__unchecked: Void, certificateExtensionOID: [Byte], certificateExtensionValues: [Byte])
        {
            self.certificateExtensionOID = certificateExtensionOID
            self.certificateExtensionValues = certificateExtensionValues
        }
    }
}

extension RFC_8446.Extension.OidFilters.Filter: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ filter: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector8(filter.certificateExtensionOID, into: &buffer)
        RFC_8446.Wire.appendVector16(filter.certificateExtensionValues, into: &buffer)
    }
}

extension RFC_8446.Wire.Reader {

    mutating func oidFilter() throws(RFC_8446.Wire.Error) -> RFC_8446.Extension.OidFilters.Filter {
        let oid = try vector8()
        let values = try vector16()
        return RFC_8446.Extension.OidFilters.Filter(
            __unchecked: (),
            certificateExtensionOID: oid,
            certificateExtensionValues: values
        )
    }
}
