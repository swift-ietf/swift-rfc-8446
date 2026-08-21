extension RFC_8446.Alert {

    public struct Level: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_8446.Alert.Level {

    public static let warning = Self(__unchecked: (), rawValue: 1)

    public static let fatal = Self(__unchecked: (), rawValue: 2)
}
