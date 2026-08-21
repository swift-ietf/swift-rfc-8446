extension RFC_8446.Handshake.ClientHello {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidRandomLength(_ count: Int)

        case invalidSessionIDLength(_ count: Int)

        case invalidCipherSuiteCount(_ count: Int)

        case invalidCompressionMethodsLength(_ count: Int)

        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.ClientHello.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS ClientHello truncated"

        case .trailingData(let remaining):
            return "TLS ClientHello has \(remaining) trailing bytes"

        case .invalidRandomLength(let count):
            return "TLS ClientHello random length invalid: \(count) bytes (expected 32)"

        case .invalidSessionIDLength(let count):
            return "TLS ClientHello legacy_session_id length invalid: \(count) bytes (max 32)"

        case .invalidCipherSuiteCount(let count):
            return "TLS ClientHello cipher_suites count invalid: \(count) (expected 1...32767)"

        case .invalidCompressionMethodsLength(let count):
            return
                "TLS ClientHello legacy_compression_methods length invalid: \(count) bytes (expected 1...255)"

        case .extensionsTooLong(let byteCount):
            return "TLS ClientHello extensions too long: \(byteCount) bytes (max 65535)"
        }
    }
}
