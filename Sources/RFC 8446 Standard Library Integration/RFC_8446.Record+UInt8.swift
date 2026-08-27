internal import Byte
public import RFC_8446

extension RFC_8446.Record {

    @_disfavoredOverload
    public init(
        contentType: RFC_8446.ContentType,
        fragment: [UInt8]
    ) throws(RFC_8446.Record.Error) {
        try self.init(contentType: contentType, fragment: fragment.map(Byte.init))
    }
}
