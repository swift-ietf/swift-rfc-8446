public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {

    public struct CertificateVerify: Sendable, Hashable {

        public let algorithm: RFC_8446.Extension.SignatureScheme

        public let signature: [Byte]

        public init(
            algorithm: RFC_8446.Extension.SignatureScheme,
            signature: [Byte]
        ) throws(Error) {
            guard signature.count <= 0xFFFF else {
                throw Error.signatureTooLong(signature.count)
            }
            self.algorithm = algorithm
            self.signature = signature
        }

        init(__unchecked: Void, algorithm: RFC_8446.Extension.SignatureScheme, signature: [Byte]) {
            self.algorithm = algorithm
            self.signature = signature
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .certificateVerify

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.CertificateVerify: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ verify: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: verify.algorithm.rawValue.bytes(endianness: .big))
        RFC_8446.Wire.appendVector16(verify.signature, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let algorithm = try reader.uint16()
            let signature = try reader.vector16()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                algorithm: RFC_8446.Extension.SignatureScheme(rawValue: algorithm),
                signature: signature
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
