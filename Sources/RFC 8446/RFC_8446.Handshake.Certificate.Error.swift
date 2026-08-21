extension RFC_8446.Handshake.Certificate {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidContextLength(_ count: Int)

        case invalidCertificateDataLength(_ count: Int)

        case entryExtensionsTooLong(_ byteCount: Int)

        case certificateListTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.Certificate.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS Certificate truncated"

        case .trailingData(let remaining):
            return "TLS Certificate has \(remaining) trailing bytes"

        case .invalidContextLength(let count):
            return "TLS Certificate context length invalid: \(count) bytes (max 255)"

        case .invalidCertificateDataLength(let count):
            return
                "TLS Certificate cert_data length invalid: \(count) bytes (expected 1...16777215)"

        case .entryExtensionsTooLong(let byteCount):
            return "TLS CertificateEntry extensions too long: \(byteCount) bytes (max 65535)"

        case .certificateListTooLong(let byteCount):
            return "TLS Certificate certificate_list too long: \(byteCount) bytes"
        }
    }
}
