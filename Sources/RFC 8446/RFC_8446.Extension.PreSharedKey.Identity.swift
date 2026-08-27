public import Binary_Serializable

extension RFC_8446.Extension.PreSharedKey {

    public struct Identity: Sendable, Hashable {

        public let identity: [Byte]

        public let obfuscatedTicketAge: UInt32

        public init(
            identity: [Byte],
            obfuscatedTicketAge: UInt32
        ) throws(RFC_8446.Extension.PreSharedKey.Error) {
            guard (1...0xFFFF).contains(identity.count) else {
                throw .invalidIdentityLength(identity.count)
            }
            self.identity = identity
            self.obfuscatedTicketAge = obfuscatedTicketAge
        }

        init(__unchecked: Void, identity: [Byte], obfuscatedTicketAge: UInt32) {
            self.identity = identity
            self.obfuscatedTicketAge = obfuscatedTicketAge
        }
    }
}

extension RFC_8446.Extension.PreSharedKey.Identity: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ identity: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector16(identity.identity, into: &buffer)
        buffer.append(contentsOf: identity.obfuscatedTicketAge.bytes(endianness: .big))
    }
}

extension RFC_8446.Wire.Reader {

    mutating func pskIdentity() throws(RFC_8446.Wire.Error)
        -> RFC_8446.Extension.PreSharedKey.Identity
    {
        let identity = try vector16()
        let age = try uint32()
        return RFC_8446.Extension.PreSharedKey.Identity(
            __unchecked: (),
            identity: identity,
            obfuscatedTicketAge: age
        )
    }
}
