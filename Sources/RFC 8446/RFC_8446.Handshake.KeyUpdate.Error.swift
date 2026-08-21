extension RFC_8446.Handshake.KeyUpdate {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.KeyUpdate.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS KeyUpdate truncated"

        case .trailingData(let remaining):
            return "TLS KeyUpdate has \(remaining) trailing bytes"
        }
    }
}
