extension RFC_8446.Handshake.NewSessionTicket {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidNonceLength(_ count: Int)

        case invalidTicketLength(_ count: Int)

        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.NewSessionTicket.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS NewSessionTicket truncated"

        case .trailingData(let remaining):
            return "TLS NewSessionTicket has \(remaining) trailing bytes"

        case .invalidNonceLength(let count):
            return "TLS NewSessionTicket nonce length invalid: \(count) bytes (max 255)"

        case .invalidTicketLength(let count):
            return "TLS NewSessionTicket ticket length invalid: \(count) bytes (expected 1...65535)"

        case .extensionsTooLong(let byteCount):
            return "TLS NewSessionTicket extensions too long: \(byteCount) bytes (max 65534)"
        }
    }
}
