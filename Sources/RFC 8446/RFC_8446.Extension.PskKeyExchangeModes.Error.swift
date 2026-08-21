extension RFC_8446.Extension.PskKeyExchangeModes {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidModeCount(_ count: Int)
    }
}

extension RFC_8446.Extension.PskKeyExchangeModes.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS psk_key_exchange_modes truncated"

        case .trailingData(let remaining):
            return "TLS psk_key_exchange_modes has \(remaining) trailing bytes"

        case .invalidModeCount(let count):
            return "TLS psk_key_exchange_modes mode count invalid: \(count) (expected 1...255)"
        }
    }
}
