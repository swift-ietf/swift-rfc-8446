extension RFC_8446.Extension.Data {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case dataTooLong(_ count: Int)
    }
}

extension RFC_8446.Extension.Data.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS extension truncated"

        case .trailingData(let remaining):
            return "TLS extension has \(remaining) trailing bytes"

        case .dataTooLong(let count):
            return "TLS extension_data too long: \(count) bytes (max 65535)"
        }
    }
}
