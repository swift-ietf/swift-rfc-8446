public import Binary_Serializable_Primitives

extension RFC_8446.Handshake.Certificate {

    public struct Entry: Sendable, Hashable {

        public let certificateData: [Byte]

        public let extensions: [RFC_8446.Extension.Data]

        public init(
            certificateData: [Byte],
            extensions: [RFC_8446.Extension.Data] = []
        ) throws(RFC_8446.Handshake.Certificate.Error) {
            guard (1...0xFF_FFFF).contains(certificateData.count) else {
                throw .invalidCertificateDataLength(certificateData.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw .entryExtensionsTooLong(blockLength)
            }
            self.certificateData = certificateData
            self.extensions = extensions
        }

        init(__unchecked: Void, certificateData: [Byte], extensions: [RFC_8446.Extension.Data]) {
            self.certificateData = certificateData
            self.extensions = extensions
        }
    }
}

extension RFC_8446.Handshake.Certificate.Entry: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ entry: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector24(entry.certificateData, into: &buffer)
        RFC_8446.Wire.appendExtensions(entry.extensions, into: &buffer)
    }
}

extension RFC_8446.Wire.Reader {

    mutating func certificateEntry() throws(RFC_8446.Wire.Error)
        -> RFC_8446.Handshake.Certificate.Entry
    {
        let data = try vector24()
        let entryExtensions = try extensions()
        return RFC_8446.Handshake.Certificate.Entry(
            __unchecked: (),
            certificateData: data,
            extensions: entryExtensions
        )
    }
}
