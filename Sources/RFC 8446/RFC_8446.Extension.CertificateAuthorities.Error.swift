extension RFC_8446.Extension.CertificateAuthorities {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidAuthorityLength(_ count: Int)

        case authoritiesTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.CertificateAuthorities.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS certificate_authorities truncated"

        case .trailingData(let remaining):
            return "TLS certificate_authorities has \(remaining) trailing bytes"

        case .invalidAuthorityLength(let count):
            return
                "TLS certificate_authorities authority length invalid: \(count) bytes (expected 1...65535)"

        case .authoritiesTooLong(let byteCount):
            return "TLS certificate_authorities too long: \(byteCount) bytes (max 65533)"
        }
    }
}
