public import Binary_Serializable

extension RFC_8446.Extension {

    public struct CertificateAuthorities: Sendable, Hashable {

        public let authorities: [[Byte]]

        public init(authorities: [[Byte]]) throws(Error) {
            for authority in authorities {
                guard (1...0xFFFF).contains(authority.count) else {
                    throw Error.invalidAuthorityLength(authority.count)
                }
            }
            let blockLength = authorities.reduce(0) { $0 + 2 + $1.count }
            guard blockLength <= 0xFFFD else {
                throw Error.authoritiesTooLong(blockLength)
            }
            self.authorities = authorities
        }

        init(__unchecked: Void, authorities: [[Byte]]) {
            self.authorities = authorities
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .certificateAuthorities

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.CertificateAuthorities: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for authority in value.authorities {
            RFC_8446.Wire.appendVector16(authority, into: &block)
        }
        RFC_8446.Wire.appendVector16(block, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var authorities: [[Byte]] = []
            while !sub.isAtEnd {
                authorities.append(try sub.vector16())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), authorities: authorities)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
