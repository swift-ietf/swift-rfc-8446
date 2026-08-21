extension RFC_8446.Extension.Cookie {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidCookieLength(_ count: Int)
    }
}

extension RFC_8446.Extension.Cookie.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS cookie truncated"

        case .trailingData(let remaining):
            return "TLS cookie has \(remaining) trailing bytes"

        case .invalidCookieLength(let count):
            return "TLS cookie length invalid: \(count) bytes (expected 1...65533)"
        }
    }
}
