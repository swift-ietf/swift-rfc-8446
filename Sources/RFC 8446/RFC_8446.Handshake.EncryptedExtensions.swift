public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {

    public struct EncryptedExtensions: Sendable, Hashable {

        public let extensions: [RFC_8446.Extension.Data]

        public init(extensions: [RFC_8446.Extension.Data]) throws(Error) {
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.extensions = extensions
        }

        init(__unchecked: Void, extensions: [RFC_8446.Extension.Data]) {
            self.extensions = extensions
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .encryptedExtensions

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.EncryptedExtensions: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendExtensions(value.extensions, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(__unchecked: (), extensions: extensions)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
