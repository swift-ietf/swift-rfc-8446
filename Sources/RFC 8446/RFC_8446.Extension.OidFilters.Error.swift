extension RFC_8446.Extension.OidFilters {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidOIDLength(_ count: Int)

        case valuesTooLong(_ count: Int)

        case filtersTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.OidFilters.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS oid_filters truncated"

        case .trailingData(let remaining):
            return "TLS oid_filters has \(remaining) trailing bytes"

        case .invalidOIDLength(let count):
            return "TLS oid_filters OID length invalid: \(count) bytes (expected 1...255)"

        case .valuesTooLong(let count):
            return "TLS oid_filters values too long: \(count) bytes (max 65535)"

        case .filtersTooLong(let byteCount):
            return "TLS oid_filters too long: \(byteCount) bytes (max 65533)"
        }
    }
}
