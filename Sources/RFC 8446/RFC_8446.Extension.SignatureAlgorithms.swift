public import Binary_Serializable

extension RFC_8446.Extension {

    public struct SignatureAlgorithms: Sendable, Hashable {

        public let supportedSignatureAlgorithms: [SignatureScheme]

        public init(supportedSignatureAlgorithms: [SignatureScheme]) throws(Error) {
            guard (1...32766).contains(supportedSignatureAlgorithms.count) else {
                throw Error.invalidAlgorithmCount(supportedSignatureAlgorithms.count)
            }
            self.supportedSignatureAlgorithms = supportedSignatureAlgorithms
        }

        init(__unchecked: Void, supportedSignatureAlgorithms: [SignatureScheme]) {
            self.supportedSignatureAlgorithms = supportedSignatureAlgorithms
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .signatureAlgorithms

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.SignatureAlgorithms: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendUInt16List(
            value.supportedSignatureAlgorithms.map(\.rawValue),
            into: &buffer
        )
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let values = try reader.uint16List()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                supportedSignatureAlgorithms: values.map(
                    RFC_8446.Extension.SignatureScheme.init(rawValue:)
                )
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
