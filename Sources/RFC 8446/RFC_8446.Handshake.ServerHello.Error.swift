extension RFC_8446.Handshake.ServerHello {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidRandomLength(_ count: Int)

        case invalidSessionIDEchoLength(_ count: Int)

        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.ServerHello.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS ServerHello truncated"

        case .trailingData(let remaining):
            return "TLS ServerHello has \(remaining) trailing bytes"

        case .invalidRandomLength(let count):
            return "TLS ServerHello random length invalid: \(count) bytes (expected 32)"

        case .invalidSessionIDEchoLength(let count):
            return "TLS ServerHello legacy_session_id_echo length invalid: \(count) bytes (max 32)"

        case .extensionsTooLong(let byteCount):
            return "TLS ServerHello extensions too long: \(byteCount) bytes (max 65535)"
        }
    }
}
