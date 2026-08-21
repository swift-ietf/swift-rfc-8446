extension RFC_8446.Extension.SignatureAlgorithmsCert {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case invalidAlgorithmCount(_ count: Int)
    }
}

extension RFC_8446.Extension.SignatureAlgorithmsCert.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS signature_algorithms_cert truncated"

        case .trailingData(let remaining):
            return "TLS signature_algorithms_cert has \(remaining) trailing bytes"

        case .invalidAlgorithmCount(let count):
            return
                "TLS signature_algorithms_cert algorithm count invalid: \(count) (expected 1...32766)"
        }
    }
}
