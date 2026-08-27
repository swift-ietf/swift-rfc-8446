internal import Binary_Serializable

extension RFC_8446.Wire {

    static func appendUInt24<Buffer: RangeReplaceableCollection>(
        _ value: Int,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(UInt8((value >> 16) & 0xFF)))
        buffer.append(Byte(UInt8((value >> 8) & 0xFF)))
        buffer.append(Byte(UInt8(value & 0xFF)))
    }

    static func extensionsBlockLength(_ extensions: [RFC_8446.Extension.Data]) -> Int {
        extensions.reduce(0) { $0 + 4 + $1.data.count }
    }

    static func appendVector8<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(Byte(UInt8(bytes.count)))
        buffer.append(contentsOf: bytes)
    }

    static func appendVector16<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: UInt16(bytes.count).bytes(endianness: .big))
        buffer.append(contentsOf: bytes)
    }

    static func appendVector24<Buffer: RangeReplaceableCollection>(
        _ bytes: [Byte],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        appendUInt24(bytes.count, into: &buffer)
        buffer.append(contentsOf: bytes)
    }

    static func appendUInt16List<Buffer: RangeReplaceableCollection>(
        _ values: [UInt16],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for value in values {
            block.append(contentsOf: value.bytes(endianness: .big))
        }
        appendVector16(block, into: &buffer)
    }

    static func appendExtensions<Buffer: RangeReplaceableCollection>(
        _ extensions: [RFC_8446.Extension.Data],
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for ext in extensions {
            RFC_8446.Extension.Data.serialize(ext, into: &block)
        }
        appendVector16(block, into: &buffer)
    }
}
