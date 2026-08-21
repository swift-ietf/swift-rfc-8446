public import Binary_Serializable_Primitives

extension RFC_8446.Extension {

    public struct Cookie: Sendable, Hashable {

        public let cookie: [Byte]

        public init(cookie: [Byte]) throws(Error) {
            guard (1...0xFFFD).contains(cookie.count) else {
                throw Error.invalidCookieLength(cookie.count)
            }
            self.cookie = cookie
        }

        init(__unchecked: Void, cookie: [Byte]) {
            self.cookie = cookie
        }

        public static let extensionType: RFC_8446.Extension.ExtensionType = .cookie

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

extension RFC_8446.Extension.Cookie: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector16(value.cookie, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let cookie = try reader.vector16()
            try reader.expectEnd()
            self.init(__unchecked: (), cookie: cookie)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
