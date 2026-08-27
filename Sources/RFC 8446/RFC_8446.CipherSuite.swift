import Radix_Formatter

extension RFC_8446 {

    public struct CipherSuite: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public static let aes128GcmSha256 = Self(__unchecked: (), rawValue: 0x1301)

        public static let aes256GcmSha384 = Self(__unchecked: (), rawValue: 0x1302)

        public static let chacha20Poly1305Sha256 = Self(__unchecked: (), rawValue: 0x1303)

        public static let aes128CcmSha256 = Self(__unchecked: (), rawValue: 0x1304)

        public static let aes128Ccm8Sha256 = Self(__unchecked: (), rawValue: 0x1305)

        public var isTLS13: Bool {
            rawValue >= 0x1301 && rawValue <= 0x1305
        }

        public var aeadAlgorithm: String? {
            switch rawValue {
            case 0x1301: return "AES-128-GCM"
            case 0x1302: return "AES-256-GCM"
            case 0x1303: return "ChaCha20-Poly1305"
            case 0x1304: return "AES-128-CCM"
            case 0x1305: return "AES-128-CCM-8"
            default: return nil
            }
        }

        public var hashAlgorithm: String? {
            switch rawValue {
            case 0x1301, 0x1303, 0x1304, 0x1305:
                return "SHA-256"

            case 0x1302:
                return "SHA-384"

            default:
                return nil
            }
        }

        public var keyLength: Int? {
            switch rawValue {
            case 0x1301, 0x1304, 0x1305: return 16
            case 0x1302, 0x1303: return 32
            default: return nil
            }
        }
    }
}

extension RFC_8446.CipherSuite: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0x1301: return "TLS_AES_128_GCM_SHA256"
        case 0x1302: return "TLS_AES_256_GCM_SHA384"
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256"
        case 0x1304: return "TLS_AES_128_CCM_SHA256"
        case 0x1305: return "TLS_AES_128_CCM_8_SHA256"

        default:
            return
                "CipherSuite(\(rawValue.formatted(Radix.Formatter.hex.zeroPadded(width: 4).prefix)))"
        }
    }
}
