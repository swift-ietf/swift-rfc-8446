extension RFC_8446.Extension.KeyShare {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidKeyExchangeLength(_ count: Int)

        case clientSharesTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.KeyShare.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS key_share truncated"

        case .trailingData(let remaining):
            return "TLS key_share has \(remaining) trailing bytes"

        case .invalidKeyExchangeLength(let count):
            return "TLS key_share key_exchange length invalid: \(count) bytes (expected 1...65531)"

        case .clientSharesTooLong(let byteCount):
            return "TLS key_share client_shares too long: \(byteCount) bytes (max 65533)"
        }
    }
}
