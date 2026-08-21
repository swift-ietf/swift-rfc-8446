public import Binary_Serializable_Primitives

extension RFC_8446.Extension {

    public struct PskKeyExchangeModes: Sendable, Hashable {

        public let keModes: [PskKeyExchangeMode]

        public init(keModes: [PskKeyExchangeMode]) throws(Error) {
            guard (1...255).contains(keModes.count) else {
                throw Error.invalidModeCount(keModes.count)
            }
            self.keModes = keModes
        }

        init(__unchecked: Void, keModes: [PskKeyExchangeMode]) {
            self.keModes = keModes
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .pskKeyExchangeModes

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.PskKeyExchangeModes: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        let modeBytes = value.keModes.map { Byte($0.rawValue) }
        RFC_8446.Wire.appendVector8(modeBytes, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let modeBytes = try reader.vector8()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                keModes: modeBytes.map {
                    RFC_8446.Extension.PskKeyExchangeMode(rawValue: $0.underlying)
                }
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
