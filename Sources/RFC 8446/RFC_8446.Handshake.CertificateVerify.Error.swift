extension RFC_8446.Handshake.CertificateVerify {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case signatureTooLong(_ count: Int)
    }
}

extension RFC_8446.Handshake.CertificateVerify.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS CertificateVerify truncated"

        case .trailingData(let remaining):
            return "TLS CertificateVerify has \(remaining) trailing bytes"

        case .signatureTooLong(let count):
            return "TLS CertificateVerify signature too long: \(count) bytes (max 65535)"
        }
    }
}
