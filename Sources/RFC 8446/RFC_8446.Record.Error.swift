extension RFC_8446.Record {

    public enum Error: Swift.Error, Sendable, Equatable {

        case fragmentTooLarge(_ size: Int)

        case truncated(_ size: Int)
    }
}

extension RFC_8446.Record.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .fragmentTooLarge(let size):
            return
                "TLS record fragment too large: \(size) bytes (max \(RFC_8446.Record.Limits.maxPlaintextLength))"

        case .truncated(let size):
            return "TLS record truncated: \(size) bytes"
        }
    }
}
