extension RFC_8446.KeySchedule.HkdfLabel {

    public enum Error: Swift::Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidLabelLength(_ count: Int)

        case invalidContextLength(_ count: Int)
    }
}

extension RFC_8446.KeySchedule.HkdfLabel.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS HkdfLabel truncated"

        case .trailingData(let remaining):
            return "TLS HkdfLabel has \(remaining) trailing bytes"

        case .invalidLabelLength(let count):
            return "TLS HkdfLabel label length invalid: \(count) bytes (expected 7...255)"

        case .invalidContextLength(let count):
            return "TLS HkdfLabel context length invalid: \(count) bytes (expected 0...255)"
        }
    }
}
