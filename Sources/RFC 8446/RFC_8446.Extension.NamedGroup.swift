extension RFC_8446.Extension {

    public struct NamedGroup: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_8446.Extension.NamedGroup {

    public static let secp256r1 = Self(__unchecked: (), rawValue: 0x0017)

    public static let secp384r1 = Self(__unchecked: (), rawValue: 0x0018)

    public static let secp521r1 = Self(__unchecked: (), rawValue: 0x0019)

    public static let x25519 = Self(__unchecked: (), rawValue: 0x001D)

    public static let x448 = Self(__unchecked: (), rawValue: 0x001E)
}

extension RFC_8446.Extension.NamedGroup {

    public static let ffdhe2048 = Self(__unchecked: (), rawValue: 0x0100)

    public static let ffdhe3072 = Self(__unchecked: (), rawValue: 0x0101)

    public static let ffdhe4096 = Self(__unchecked: (), rawValue: 0x0102)

    public static let ffdhe6144 = Self(__unchecked: (), rawValue: 0x0103)

    public static let ffdhe8192 = Self(__unchecked: (), rawValue: 0x0104)
}
