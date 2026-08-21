extension RFC_8446.Extension.PreSharedKey {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidIdentityLength(_ count: Int)

        case invalidBinderLength(_ count: Int)

        case offeredPsksTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.PreSharedKey.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS pre_shared_key truncated"

        case .trailingData(let remaining):
            return "TLS pre_shared_key has \(remaining) trailing bytes"

        case .invalidIdentityLength(let count):
            return "TLS pre_shared_key identity length invalid: \(count) bytes (expected 1...65535)"

        case .invalidBinderLength(let count):
            return "TLS pre_shared_key binder length invalid: \(count) bytes (expected 32...255)"

        case .offeredPsksTooLong(let byteCount):
            return "TLS pre_shared_key OfferedPsks too long: \(byteCount) bytes (max 65535)"
        }
    }
}
