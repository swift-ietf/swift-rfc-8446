extension RFC_8446.Extension.SupportedVersions {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidVersionCount(_ count: Int)
    }
}

extension RFC_8446.Extension.SupportedVersions.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS supported_versions truncated"

        case .trailingData(let remaining):
            return "TLS supported_versions has \(remaining) trailing bytes"

        case .invalidVersionCount(let count):
            return "TLS supported_versions version count invalid: \(count) (expected 1...127)"
        }
    }
}
