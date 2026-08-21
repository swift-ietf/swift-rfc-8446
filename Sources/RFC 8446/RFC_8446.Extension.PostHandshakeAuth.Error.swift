extension RFC_8446.Extension.PostHandshakeAuth {

    public enum Error: Swift.Error, Sendable, Equatable {

        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.PostHandshakeAuth.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS post_handshake_auth has \(remaining) trailing bytes (body must be empty)"
        }
    }
}
