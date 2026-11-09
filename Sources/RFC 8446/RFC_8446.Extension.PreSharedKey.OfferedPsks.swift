public import Binary

extension RFC_8446.Extension.PreSharedKey {

    public struct OfferedPsks: Sendable, Hashable {

        public let identities: [Identity]

        public let binders: [[Byte]]

        public init(
            identities: [Identity],
            binders: [[Byte]]
        ) throws(RFC_8446.Extension.PreSharedKey.Error) {
            guard !identities.isEmpty else {
                throw .invalidIdentityCount(identities.count)
            }
            guard binders.count == identities.count else {
                throw .binderCountMismatch(identities: identities.count, binders: binders.count)
            }
            for binder in binders {
                guard (32...255).contains(binder.count) else {
                    throw .invalidBinderLength(binder.count)
                }
            }
            let identitiesBlock = identities.reduce(0) { $0 + 2 + $1.identity.count + 4 }
            let bindersBlock = binders.reduce(0) { $0 + 1 + $1.count }
            let total = 2 + identitiesBlock + 2 + bindersBlock
            guard total <= 0xFFFF else {
                throw .offeredPsksTooLong(total)
            }
            self.identities = identities
            self.binders = binders
        }

        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.PreSharedKey.extensionType,
                data: self.bytes
            )
        }
    }
}

extension RFC_8446.Extension.PreSharedKey.OfferedPsks: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var identitiesBlock: [Byte] = []
        for identity in value.identities {
            RFC_8446.Extension.PreSharedKey.Identity.serialize(identity, into: &identitiesBlock)
        }
        RFC_8446.Wire.appendVector16(identitiesBlock, into: &buffer)

        var bindersBlock: [Byte] = []
        for binder in value.binders {
            RFC_8446.Wire.appendVector8(binder, into: &bindersBlock)
        }
        RFC_8446.Wire.appendVector16(bindersBlock, into: &buffer)
    }

    public init<Bytes: Swift::Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.PreSharedKey.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        var identities: [RFC_8446.Extension.PreSharedKey.Identity] = []
        var binders: [[Byte]] = []
        do {
            let identitiesBlock = try reader.vector16()
            var identitiesReader = RFC_8446.Wire.Reader(identitiesBlock)
            while !identitiesReader.isAtEnd {
                identities.append(try identitiesReader.pskIdentity())
            }

            let bindersBlock = try reader.vector16()
            var bindersReader = RFC_8446.Wire.Reader(bindersBlock)
            while !bindersReader.isAtEnd {
                binders.append(try bindersReader.vector8())
            }

            try reader.expectEnd()
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
        try self.init(
            identities: identities.map { (identity) throws(RFC_8446.Extension.PreSharedKey.Error) in
                try RFC_8446.Extension.PreSharedKey.Identity(
                    identity: identity.identity,
                    obfuscatedTicketAge: identity.obfuscatedTicketAge
                )
            },
            binders: binders
        )
    }
}
