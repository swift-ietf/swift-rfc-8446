extension RFC_8446.Wire {

    enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case lengthOverflow

        case trailingData(_ remaining: Int)
    }
}
