extension RFC_8446.Alert {

    public struct Description: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }
}

extension RFC_8446.Alert.Description {

    public static let closeNotify = Self(__unchecked: (), rawValue: 0)
}

extension RFC_8446.Alert.Description {

    public static let unexpectedMessage = Self(__unchecked: (), rawValue: 10)

    public static let badRecordMac = Self(__unchecked: (), rawValue: 20)

    public static let recordOverflow = Self(__unchecked: (), rawValue: 22)

    public static let handshakeFailure = Self(__unchecked: (), rawValue: 40)

    public static let badCertificate = Self(__unchecked: (), rawValue: 42)

    public static let unsupportedCertificate = Self(__unchecked: (), rawValue: 43)

    public static let certificateRevoked = Self(__unchecked: (), rawValue: 44)

    public static let certificateExpired = Self(__unchecked: (), rawValue: 45)

    public static let certificateUnknown = Self(__unchecked: (), rawValue: 46)

    public static let illegalParameter = Self(__unchecked: (), rawValue: 47)

    public static let unknownCA = Self(__unchecked: (), rawValue: 48)

    public static let accessDenied = Self(__unchecked: (), rawValue: 49)

    public static let decodeError = Self(__unchecked: (), rawValue: 50)

    public static let decryptError = Self(__unchecked: (), rawValue: 51)

    public static let protocolVersion = Self(__unchecked: (), rawValue: 70)

    public static let insufficientSecurity = Self(__unchecked: (), rawValue: 71)

    public static let internalError = Self(__unchecked: (), rawValue: 80)

    public static let inappropriateFallback = Self(__unchecked: (), rawValue: 86)

    public static let userCanceled = Self(__unchecked: (), rawValue: 90)

    public static let missingExtension = Self(__unchecked: (), rawValue: 109)

    public static let unsupportedExtension = Self(__unchecked: (), rawValue: 110)

    public static let unrecognizedName = Self(__unchecked: (), rawValue: 112)

    public static let badCertificateStatusResponse = Self(__unchecked: (), rawValue: 113)

    public static let unknownPSKIdentity = Self(__unchecked: (), rawValue: 115)

    public static let certificateRequired = Self(__unchecked: (), rawValue: 116)

    public static let noApplicationProtocol = Self(__unchecked: (), rawValue: 120)
}

extension RFC_8446.Alert.Description: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "close_notify"
        case 10: return "unexpected_message"
        case 20: return "bad_record_mac"
        case 22: return "record_overflow"
        case 40: return "handshake_failure"
        case 42: return "bad_certificate"
        case 43: return "unsupported_certificate"
        case 44: return "certificate_revoked"
        case 45: return "certificate_expired"
        case 46: return "certificate_unknown"
        case 47: return "illegal_parameter"
        case 48: return "unknown_ca"
        case 49: return "access_denied"
        case 50: return "decode_error"
        case 51: return "decrypt_error"
        case 70: return "protocol_version"
        case 71: return "insufficient_security"
        case 80: return "internal_error"
        case 86: return "inappropriate_fallback"
        case 90: return "user_canceled"
        case 109: return "missing_extension"
        case 110: return "unsupported_extension"
        case 112: return "unrecognized_name"
        case 113: return "bad_certificate_status_response"
        case 115: return "unknown_psk_identity"
        case 116: return "certificate_required"
        case 120: return "no_application_protocol"
        default: return "alert(\(rawValue))"
        }
    }
}
