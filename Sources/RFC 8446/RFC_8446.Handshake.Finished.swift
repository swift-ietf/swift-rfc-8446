public import Binary_Serializable

extension RFC_8446.Handshake {

    public struct Finished: Sendable, Hashable {

        public let verifyData: [Byte]

        public init(verifyData: [Byte]) throws(Error) {
            guard verifyData.count <= 0xFF_FFFF else {
                throw Error.verifyDataTooLong(verifyData.count)
            }
            self.verifyData = verifyData
        }

        init(__unchecked: Void, verifyData: [Byte]) {
            self.verifyData = verifyData
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .finished

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.Finished: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ finished: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: finished.verifyData)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        let verifyData = Array(bytes)
        guard verifyData.count <= 0xFF_FFFF else {
            throw Error.verifyDataTooLong(verifyData.count)
        }
        self.init(__unchecked: (), verifyData: verifyData)
    }
}
