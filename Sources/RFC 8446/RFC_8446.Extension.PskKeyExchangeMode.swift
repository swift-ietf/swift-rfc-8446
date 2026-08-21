extension RFC_8446.Extension {

    public struct PskKeyExchangeMode: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let pskKe = Self(__unchecked: (), rawValue: 0)

        public static let pskDheKe = Self(__unchecked: (), rawValue: 1)
    }
}

extension RFC_8446.Extension.PskKeyExchangeMode: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "psk_ke"
        case 1: return "psk_dhe_ke"
        default: return "psk_key_exchange_mode(\(rawValue))"
        }
    }
}
