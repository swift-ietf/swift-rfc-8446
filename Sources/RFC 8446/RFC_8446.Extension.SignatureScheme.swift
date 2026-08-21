extension RFC_8446.Extension {

    public struct SignatureScheme: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_8446.Extension.SignatureScheme {

    public static let rsaPkcs1Sha256 = Self(__unchecked: (), rawValue: 0x0401)

    public static let rsaPkcs1Sha384 = Self(__unchecked: (), rawValue: 0x0501)

    public static let rsaPkcs1Sha512 = Self(__unchecked: (), rawValue: 0x0601)
}

extension RFC_8446.Extension.SignatureScheme {

    public static let ecdsaSecp256r1Sha256 = Self(__unchecked: (), rawValue: 0x0403)

    public static let ecdsaSecp384r1Sha384 = Self(__unchecked: (), rawValue: 0x0503)

    public static let ecdsaSecp521r1Sha512 = Self(__unchecked: (), rawValue: 0x0603)
}

extension RFC_8446.Extension.SignatureScheme {

    public static let rsaPssRsaeSha256 = Self(__unchecked: (), rawValue: 0x0804)

    public static let rsaPssRsaeSha384 = Self(__unchecked: (), rawValue: 0x0805)

    public static let rsaPssRsaeSha512 = Self(__unchecked: (), rawValue: 0x0806)
}

extension RFC_8446.Extension.SignatureScheme {

    public static let ed25519 = Self(__unchecked: (), rawValue: 0x0807)

    public static let ed448 = Self(__unchecked: (), rawValue: 0x0808)
}

extension RFC_8446.Extension.SignatureScheme {

    public static let rsaPssPssSha256 = Self(__unchecked: (), rawValue: 0x0809)

    public static let rsaPssPssSha384 = Self(__unchecked: (), rawValue: 0x080A)

    public static let rsaPssPssSha512 = Self(__unchecked: (), rawValue: 0x080B)
}
