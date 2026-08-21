extension RFC_8446.Extension.SupportedGroups {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidGroupCount(_ count: Int)
    }
}

extension RFC_8446.Extension.SupportedGroups.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS supported_groups truncated"

        case .trailingData(let remaining):
            return "TLS supported_groups has \(remaining) trailing bytes"

        case .invalidGroupCount(let count):
            return "TLS supported_groups group count invalid: \(count) (expected 1...32766)"
        }
    }
}
