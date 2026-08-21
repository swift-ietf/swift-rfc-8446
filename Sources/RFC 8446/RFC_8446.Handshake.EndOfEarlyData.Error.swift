extension RFC_8446.Handshake.EndOfEarlyData {

    public enum Error: Swift.Error, Sendable, Equatable {

        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.EndOfEarlyData.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS EndOfEarlyData has \(remaining) trailing bytes (body must be empty)"
        }
    }
}
