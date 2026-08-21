extension RFC_8446.Handshake.CertificateRequest {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidContextLength(_ count: Int)

        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.CertificateRequest.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS CertificateRequest truncated"

        case .trailingData(let remaining):
            return "TLS CertificateRequest has \(remaining) trailing bytes"

        case .invalidContextLength(let count):
            return "TLS CertificateRequest context length invalid: \(count) bytes (max 255)"

        case .extensionsTooLong(let byteCount):
            return "TLS CertificateRequest extensions too long: \(byteCount) bytes (max 65535)"
        }
    }
}
