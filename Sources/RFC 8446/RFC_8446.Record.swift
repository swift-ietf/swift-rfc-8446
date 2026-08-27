public import Binary_Serializable

extension RFC_8446 {

    public struct Record: Sendable, Hashable {

        public let contentType: ContentType

        public let legacyVersion: ProtocolVersion

        public let fragment: [Byte]

        public init(
            contentType: ContentType,
            fragment: [Byte]
        ) throws(Error) {
            guard fragment.count <= Limits.maxPlaintextLength else {
                throw Error.fragmentTooLarge(fragment.count)
            }
            self.contentType = contentType
            self.legacyVersion = .legacy
            self.fragment = fragment
        }

        init(
            __unchecked: Void,
            contentType: ContentType,
            legacyVersion: ProtocolVersion,
            fragment: [Byte]
        ) {
            self.contentType = contentType
            self.legacyVersion = legacyVersion
            self.fragment = fragment
        }
    }
}

extension RFC_8446.Record: Binary.Serializable {

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ record: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(Byte(record.contentType.rawValue))

        buffer.append(contentsOf: record.legacyVersion.rawValue.bytes(endianness: .big))

        let length = UInt16(record.fragment.count)
        buffer.append(contentsOf: length.bytes(endianness: .big))

        buffer.append(contentsOf: record.fragment)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.count >= Limits.headerSize else {
            throw Error.truncated(bytes.count)
        }

        var iterator = bytes.makeIterator()

        func next() -> UInt8 {
            iterator.next()!.underlying
        }

        let ct = next()
        self.contentType = RFC_8446.ContentType(rawValue: ct)

        let vHi = next()
        let vLo = next()
        self.legacyVersion = RFC_8446.ProtocolVersion(rawValue: (UInt16(vHi) << 8) | UInt16(vLo))

        let lHi = next()
        let lLo = next()
        let length = (Int(lHi) << 8) | Int(lLo)

        guard length <= Limits.maxCiphertextLength else {
            throw Error.fragmentTooLarge(length)
        }

        guard bytes.count >= Limits.headerSize + length else {
            throw Error.truncated(bytes.count)
        }

        var fragment: [Byte] = []
        fragment.reserveCapacity(length)
        for _ in 0..<length {
            fragment.append(Byte(next()))
        }
        self.fragment = fragment
    }
}
