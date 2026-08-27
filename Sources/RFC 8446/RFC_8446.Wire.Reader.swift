internal import Binary_Serializable

extension RFC_8446.Wire {

    struct Reader {

        private let bytes: [Byte]

        private(set) var index: Int

        init(_ bytes: [Byte]) {
            self.bytes = bytes
            self.index = 0
        }

        var remaining: Int { bytes.count - index }

        var isAtEnd: Bool { index >= bytes.count }

        mutating func byte() throws(RFC_8446.Wire.Error) -> UInt8 {
            guard index < bytes.count else { throw .truncated }
            defer { index += 1 }
            return bytes[index].underlying
        }

        mutating func uint16() throws(RFC_8446.Wire.Error) -> UInt16 {
            let hi = try byte()
            let lo = try byte()
            return (UInt16(hi) << 8) | UInt16(lo)
        }

        mutating func uint24() throws(RFC_8446.Wire.Error) -> Int {
            let a = try byte()
            let b = try byte()
            let c = try byte()
            return (Int(a) << 16) | (Int(b) << 8) | Int(c)
        }

        mutating func uint32() throws(RFC_8446.Wire.Error) -> UInt32 {
            let a = try byte()
            let b = try byte()
            let c = try byte()
            let d = try byte()
            return (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | UInt32(d)
        }

        mutating func take(_ count: Int) throws(RFC_8446.Wire.Error) -> [Byte] {
            guard count >= 0 else { throw .lengthOverflow }
            guard remaining >= count else { throw .truncated }
            let slice = bytes[index..<index + count]
            index += count
            return Array(slice)
        }

        mutating func rest() -> [Byte] {
            let slice = bytes[index..<bytes.count]
            index = bytes.count
            return Array(slice)
        }

        mutating func vector8() throws(RFC_8446.Wire.Error) -> [Byte] {
            let count = Int(try byte())
            return try take(count)
        }

        mutating func vector16() throws(RFC_8446.Wire.Error) -> [Byte] {
            let count = Int(try uint16())
            return try take(count)
        }

        mutating func vector24() throws(RFC_8446.Wire.Error) -> [Byte] {
            let count = try uint24()
            return try take(count)
        }

        mutating func uint16List() throws(RFC_8446.Wire.Error) -> [UInt16] {
            let block = try vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var values: [UInt16] = []
            while !sub.isAtEnd {
                values.append(try sub.uint16())
            }
            return values
        }

        mutating func extensions() throws(RFC_8446.Wire.Error) -> [RFC_8446.Extension.Data] {
            let block = try vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var result: [RFC_8446.Extension.Data] = []
            while !sub.isAtEnd {
                let type = try sub.uint16()
                let data = try sub.vector16()
                result.append(
                    RFC_8446.Extension.Data(
                        __unchecked: (),
                        type: RFC_8446.Extension.ExtensionType(rawValue: type),
                        data: data
                    )
                )
            }
            return result
        }

        func expectEnd() throws(RFC_8446.Wire.Error) {
            guard isAtEnd else { throw .trailingData(remaining) }
        }
    }
}
