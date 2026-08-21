extension RFC_8446.Handshake.Message {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case lengthMismatch(_ declared: Int, _ available: Int)

        case bodyTooLong(_ count: Int)
    }
}

extension RFC_8446.Handshake.Message.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS handshake message truncated"

        case .lengthMismatch(let declared, let available):
            return
                "TLS handshake message length mismatch: declared \(declared), available \(available)"

        case .bodyTooLong(let count):
            return "TLS handshake message body too long: \(count) bytes (max 16777215)"
        }
    }
}
