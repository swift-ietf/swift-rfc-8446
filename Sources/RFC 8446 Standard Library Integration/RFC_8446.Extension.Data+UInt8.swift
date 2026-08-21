internal import Byte_Primitives
public import RFC_8446

extension RFC_8446.Extension.Data {

    @_disfavoredOverload
    public init(type: RFC_8446.Extension.ExtensionType, data: [UInt8]) throws(Error) {
        try self.init(type: type, data: data.map(Byte.init))
    }
}
