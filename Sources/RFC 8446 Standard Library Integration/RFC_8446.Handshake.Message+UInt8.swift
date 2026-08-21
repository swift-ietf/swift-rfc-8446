internal import Byte_Primitives
public import RFC_8446

extension RFC_8446.Handshake.Message {

    @_disfavoredOverload
    public init(type: RFC_8446.Handshake.MessageType, body: [UInt8]) throws(Error) {
        try self.init(type: type, body: body.map(Byte.init))
    }
}
