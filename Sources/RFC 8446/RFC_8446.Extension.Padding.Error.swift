extension RFC_8446.Extension.Padding {

    public enum Error: Swift.Error, Sendable, Equatable {

        case invalidPaddingLength(_ count: Int)
    }
}

extension RFC_8446.Extension.Padding.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidPaddingLength(let count):
            return "TLS padding length invalid: \(count) bytes (expected 0...65535)"
        }
    }
}
