public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {

    public struct CertificateRequest: Sendable, Hashable {

        public let certificateRequestContext: [Byte]

        public let extensions: [RFC_8446.Extension.Data]

        public init(
            certificateRequestContext: [Byte] = [],
            extensions: [RFC_8446.Extension.Data]
        ) throws(Error) {
            guard certificateRequestContext.count <= 0xFF else {
                throw Error.invalidContextLength(certificateRequestContext.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.certificateRequestContext = certificateRequestContext
            self.extensions = extensions
        }

        init(
            __unchecked: Void,
            certificateRequestContext: [Byte],
            extensions: [RFC_8446.Extension.Data]
        ) {
            self.certificateRequestContext = certificateRequestContext
            self.extensions = extensions
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .certificateRequest

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.CertificateRequest: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ request: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector8(request.certificateRequestContext, into: &buffer)
        RFC_8446.Wire.appendExtensions(request.extensions, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let context = try reader.vector8()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(__unchecked: (), certificateRequestContext: context, extensions: extensions)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
