extension RFC_8446.Handshake.Finished {

    public enum Error: Swift.Error, Sendable, Equatable {

        case verifyDataTooLong(_ count: Int)
    }
}

extension RFC_8446.Handshake.Finished.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .verifyDataTooLong(let count):
            return "TLS Finished verify_data too long: \(count) bytes (max 16777215)"
        }
    }
}
