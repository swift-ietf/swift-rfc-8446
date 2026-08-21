extension RFC_8446 {

    public struct ProtocolVersion: RawRepresentable, Sendable, Hashable, Codable, Comparable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public init(major: UInt8, minor: UInt8) {
            self.rawValue = (UInt16(major) << 8) | UInt16(minor)
        }

        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public var major: UInt8 {
            UInt8(rawValue >> 8)
        }

        public var minor: UInt8 {
            UInt8(rawValue & 0xFF)
        }

        public static let tls1_0 = Self(__unchecked: (), rawValue: 0x0301)

        public static let tls1_1 = Self(__unchecked: (), rawValue: 0x0302)

        public static let tls1_2 = Self(__unchecked: (), rawValue: 0x0303)

        public static let tls1_3 = Self(__unchecked: (), rawValue: 0x0304)

        public static let legacy = Self.tls1_2

        public static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }
}

extension RFC_8446.ProtocolVersion: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0x0300: return "SSL 3.0"
        case 0x0301: return "TLS 1.0"
        case 0x0302: return "TLS 1.1"
        case 0x0303: return "TLS 1.2"
        case 0x0304: return "TLS 1.3"
        default: return "TLS \(major).\(minor)"
        }
    }
}
