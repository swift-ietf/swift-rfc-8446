extension RFC_8446.Extension {

    public struct ExtensionType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_8446.Extension.ExtensionType {

    public static let serverName = Self(__unchecked: (), rawValue: 0)

    public static let maxFragmentLength = Self(__unchecked: (), rawValue: 1)

    public static let statusRequest = Self(__unchecked: (), rawValue: 5)

    public static let supportedGroups = Self(__unchecked: (), rawValue: 10)

    public static let signatureAlgorithms = Self(__unchecked: (), rawValue: 13)

    public static let useSRTP = Self(__unchecked: (), rawValue: 14)

    public static let heartbeat = Self(__unchecked: (), rawValue: 15)

    public static let alpn = Self(__unchecked: (), rawValue: 16)

    public static let signedCertificateTimestamp = Self(__unchecked: (), rawValue: 18)

    public static let clientCertificateType = Self(__unchecked: (), rawValue: 19)

    public static let serverCertificateType = Self(__unchecked: (), rawValue: 20)

    public static let padding = Self(__unchecked: (), rawValue: 21)

    public static let preSharedKey = Self(__unchecked: (), rawValue: 41)

    public static let earlyData = Self(__unchecked: (), rawValue: 42)

    public static let supportedVersions = Self(__unchecked: (), rawValue: 43)

    public static let cookie = Self(__unchecked: (), rawValue: 44)

    public static let pskKeyExchangeModes = Self(__unchecked: (), rawValue: 45)

    public static let certificateAuthorities = Self(__unchecked: (), rawValue: 47)

    public static let oidFilters = Self(__unchecked: (), rawValue: 48)

    public static let postHandshakeAuth = Self(__unchecked: (), rawValue: 49)

    public static let signatureAlgorithmsCert = Self(__unchecked: (), rawValue: 50)

    public static let keyShare = Self(__unchecked: (), rawValue: 51)
}

extension RFC_8446.Extension.ExtensionType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "server_name"
        case 1: return "max_fragment_length"
        case 5: return "status_request"
        case 10: return "supported_groups"
        case 13: return "signature_algorithms"
        case 14: return "use_srtp"
        case 15: return "heartbeat"
        case 16: return "application_layer_protocol_negotiation"
        case 18: return "signed_certificate_timestamp"
        case 19: return "client_certificate_type"
        case 20: return "server_certificate_type"
        case 21: return "padding"
        case 41: return "pre_shared_key"
        case 42: return "early_data"
        case 43: return "supported_versions"
        case 44: return "cookie"
        case 45: return "psk_key_exchange_modes"
        case 47: return "certificate_authorities"
        case 48: return "oid_filters"
        case 49: return "post_handshake_auth"
        case 50: return "signature_algorithms_cert"
        case 51: return "key_share"
        default: return "extension(\(rawValue))"
        }
    }
}
