public import Binary_Serializable_Primitives

extension RFC_8446.Handshake {

    public struct Certificate: Sendable, Hashable {

        public let certificateRequestContext: [Byte]

        public let certificateList: [Entry]

        public init(certificateRequestContext: [Byte] = [], certificateList: [Entry]) throws(Error)
        {
            guard certificateRequestContext.count <= 0xFF else {
                throw Error.invalidContextLength(certificateRequestContext.count)
            }
            let blockLength = certificateList.reduce(0) {
                $0 + 3 + $1.certificateData.count + 2
                    + RFC_8446.Wire.extensionsBlockLength($1.extensions)
            }
            guard blockLength <= 0xFF_FFFF - 4 - certificateRequestContext.count else {
                throw Error.certificateListTooLong(blockLength)
            }
            self.certificateRequestContext = certificateRequestContext
            self.certificateList = certificateList
        }

        init(__unchecked: Void, certificateRequestContext: [Byte], certificateList: [Entry]) {
            self.certificateRequestContext = certificateRequestContext
            self.certificateList = certificateList
        }

        public static let handshakeType: RFC_8446.Handshake.MessageType = .certificate

        public var message: RFC_8446.Handshake.Message {
            RFC_8446.Handshake.Message(__unchecked: (), type: Self.handshakeType, body: self.bytes)
        }
    }
}

extension RFC_8446.Handshake.Certificate: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ certificate: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector8(certificate.certificateRequestContext, into: &buffer)

        var entriesBlock: [Byte] = []
        for entry in certificate.certificateList {
            Entry.serialize(entry, into: &entriesBlock)
        }
        RFC_8446.Wire.appendVector24(entriesBlock, into: &buffer)
    }

    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let context = try reader.vector8()
            let entriesBlock = try reader.vector24()
            var sub = RFC_8446.Wire.Reader(entriesBlock)
            var entries: [Entry] = []
            while !sub.isAtEnd {
                entries.append(try sub.certificateEntry())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), certificateRequestContext: context, certificateList: entries)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
