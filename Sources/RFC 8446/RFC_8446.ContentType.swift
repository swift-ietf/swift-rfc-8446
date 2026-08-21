extension RFC_8446 {

    public struct ContentType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let invalid = Self(__unchecked: (), rawValue: 0)

        public static let changeCipherSpec = Self(__unchecked: (), rawValue: 20)

        public static let alert = Self(__unchecked: (), rawValue: 21)

        public static let handshake = Self(__unchecked: (), rawValue: 22)

        public static let applicationData = Self(__unchecked: (), rawValue: 23)

        public static let heartbeat = Self(__unchecked: (), rawValue: 24)
    }
}

extension RFC_8446.ContentType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "invalid"
        case 20: return "change_cipher_spec"
        case 21: return "alert"
        case 22: return "handshake"
        case 23: return "application_data"
        case 24: return "heartbeat"
        default: return "content_type(\(rawValue))"
        }
    }
}
