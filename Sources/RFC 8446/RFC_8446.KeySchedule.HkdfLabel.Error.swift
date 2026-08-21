extension RFC_8446.KeySchedule.HkdfLabel {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.KeySchedule.HkdfLabel.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS HkdfLabel truncated"

        case .trailingData(let remaining):
            return "TLS HkdfLabel has \(remaining) trailing bytes"
        }
    }
}
