extension RFC_8446.Extension.EarlyData {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.EarlyData.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS early_data truncated"

        case .trailingData(let remaining):
            return "TLS early_data has \(remaining) trailing bytes"
        }
    }
}
