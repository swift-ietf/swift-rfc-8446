extension RFC_8446.Handshake.EncryptedExtensions {

    public enum Error: Swift.Error, Sendable, Equatable {

        case truncated

        case trailingData(_ remaining: Int)

        case extensionsTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.EncryptedExtensions.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS EncryptedExtensions truncated"

        case .trailingData(let remaining):
            return "TLS EncryptedExtensions has \(remaining) trailing bytes"

        case .extensionsTooLong(let byteCount):
            return "TLS EncryptedExtensions extensions too long: \(byteCount) bytes (max 65535)"
        }
    }
}
