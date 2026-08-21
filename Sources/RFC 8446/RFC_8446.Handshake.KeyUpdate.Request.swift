extension RFC_8446.Handshake.KeyUpdate {

    public struct Request: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let updateNotRequested = Self(__unchecked: (), rawValue: 0)

        public static let updateRequested = Self(__unchecked: (), rawValue: 1)
    }
}

extension RFC_8446.Handshake.KeyUpdate.Request: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "update_not_requested"
        case 1: return "update_requested"
        default: return "key_update_request(\(rawValue))"
        }
    }
}
