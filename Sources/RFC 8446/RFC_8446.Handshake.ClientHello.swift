public import Binary_Serializable

extension RFC_8446.Handshake {

    public struct ClientHello: Sendable, Hashable {

        public let legacyVersion: RFC_8446.ProtocolVersion

        public let random: [Byte]

        public let legacySessionID: [Byte]

        public let cipherSuites: [RFC_8446.CipherSuite]

        public let legacyCompressionMethods: [Byte]

        public let extensions: [RFC_8446.Extension.Data]

        public init(
            legacyVersion: RFC_8446.ProtocolVersion = .legacy,
            random: [Byte],
            legacySessionID: [Byte] = [],
            cipherSuites: [RFC_8446.CipherSuite],
            legacyCompressionMethods: [Byte] = [Byte(0)],
            extensions: [RFC_8446.Extension.Data]
        ) throws(Error) {
            guard random.count == 32 else {
                throw Error.invalidRandomLength(random.count)
            }
            guard legacySessionID.count <= 32 else {
                throw Error.invalidSessionIDLength(legacySessionID.count)
            }
            guard (1...32767).contains(cipherSuites.count) else {
                throw Error.invalidCipherSuiteCount(cipherSuites.count)
            }
            guard (1...0xFF).contains(legacyCompressionMethods.count) else {
                throw Error.invalidCompressionMethodsLength(legacyCompressionMethods.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionID = legacySessionID
            self.cipherSuites = cipherSuites
            self.legacyCompressionMethods = legacyCompressionMethods
            self.extensions = extensions
        }

        init(
            __unchecked: Void,
            legacyVersion: RFC_8446.ProtocolVersion,
            random: [Byte],
            legacySessionID: [Byte],
            cipherSuites: [RFC_8446.CipherSuite],
            legacyCompressionMethods: [Byte],
            extensions: [RFC_8446.Extension.Data]
        ) {
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionID = legacySessionID
            self.cipherSuites = cipherSuites
            self.legacyCompressionMethods = legacyCompressionMethods
            self.extensions = extensions
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .clientHello

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.ClientHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ hello: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: hello.legacyVersion.rawValue.bytes(endianness: .big))
        buffer.append(contentsOf: hello.random)
        RFC_8446.Wire.appendVector8(hello.legacySessionID, into: &buffer)
        RFC_8446.Wire.appendUInt16List(hello.cipherSuites.map(\.rawValue), into: &buffer)
        RFC_8446.Wire.appendVector8(hello.legacyCompressionMethods, into: &buffer)
        RFC_8446.Wire.appendExtensions(hello.extensions, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let version = try reader.uint16()
            let random = try reader.take(32)
            let sessionID = try reader.vector8()
            let suites = try reader.uint16List()
            let compression = try reader.vector8()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                legacyVersion: RFC_8446.ProtocolVersion(rawValue: version),
                random: random,
                legacySessionID: sessionID,
                cipherSuites: suites.map(RFC_8446.CipherSuite.init(rawValue:)),
                legacyCompressionMethods: compression,
                extensions: extensions
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
