public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {

    public struct ServerHello: Sendable, Hashable {

        public let legacyVersion: RFC_8446.ProtocolVersion

        public let random: [Byte]

        public let legacySessionIDEcho: [Byte]

        public let cipherSuite: RFC_8446.CipherSuite

        public let legacyCompressionMethod: UInt8

        public let extensions: [RFC_8446.Extension.Data]

        public init(
            legacyVersion: RFC_8446.ProtocolVersion = .legacy,
            random: [Byte],
            legacySessionIDEcho: [Byte] = [],
            cipherSuite: RFC_8446.CipherSuite,
            legacyCompressionMethod: UInt8 = 0,
            extensions: [RFC_8446.Extension.Data]
        ) throws(Error) {
            guard random.count == 32 else {
                throw Error.invalidRandomLength(random.count)
            }
            guard legacySessionIDEcho.count <= 32 else {
                throw Error.invalidSessionIDEchoLength(legacySessionIDEcho.count)
            }
            let blockLength = RFC_8446.Wire.extensionsBlockLength(extensions)
            guard blockLength <= 0xFFFF else {
                throw Error.extensionsTooLong(blockLength)
            }
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionIDEcho = legacySessionIDEcho
            self.cipherSuite = cipherSuite
            self.legacyCompressionMethod = legacyCompressionMethod
            self.extensions = extensions
        }

        init(
            __unchecked: Void,
            legacyVersion: RFC_8446.ProtocolVersion,
            random: [Byte],
            legacySessionIDEcho: [Byte],
            cipherSuite: RFC_8446.CipherSuite,
            legacyCompressionMethod: UInt8,
            extensions: [RFC_8446.Extension.Data]
        ) {
            self.legacyVersion = legacyVersion
            self.random = random
            self.legacySessionIDEcho = legacySessionIDEcho
            self.cipherSuite = cipherSuite
            self.legacyCompressionMethod = legacyCompressionMethod
            self.extensions = extensions
        }

        public static let helloRetryRequestRandom: [Byte] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ]

        public var isHelloRetryRequest: Bool {
            random == Self.helloRetryRequestRandom
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .serverHello

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ hello: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: hello.legacyVersion.rawValue.bytes(endianness: .big))
        buffer.append(contentsOf: hello.random)
        RFC_8446.Wire.appendVector8(hello.legacySessionIDEcho, into: &buffer)
        buffer.append(contentsOf: hello.cipherSuite.rawValue.bytes(endianness: .big))
        buffer.append(Byte(hello.legacyCompressionMethod))
        RFC_8446.Wire.appendExtensions(hello.extensions, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let version = try reader.uint16()
            let random = try reader.take(32)
            let sessionID = try reader.vector8()
            let suite = try reader.uint16()
            let compression = try reader.byte()
            let extensions = try reader.extensions()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                legacyVersion: RFC_8446.ProtocolVersion(rawValue: version),
                random: random,
                legacySessionIDEcho: sessionID,
                cipherSuite: RFC_8446.CipherSuite(rawValue: suite),
                legacyCompressionMethod: compression,
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
