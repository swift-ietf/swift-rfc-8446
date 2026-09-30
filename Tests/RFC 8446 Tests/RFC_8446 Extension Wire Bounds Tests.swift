import Testing

@testable import RFC_8446

@Suite
struct `Extension wire bounds` {
    private static let emptyVector16: [Byte] = [Byte(0), Byte(0)]

    @Test
    func `an empty supported groups list is refused`() {
        #expect(throws: RFC_8446.Extension.SupportedGroups.Error.self) {
            try RFC_8446.Extension.SupportedGroups(binary: Self.emptyVector16)
        }
    }

    @Test
    func `an empty signature algorithms list is refused`() {
        #expect(throws: RFC_8446.Extension.SignatureAlgorithms.Error.self) {
            try RFC_8446.Extension.SignatureAlgorithms(binary: Self.emptyVector16)
        }
    }

    @Test
    func `an empty certificate signature algorithms list is refused`() {
        #expect(throws: RFC_8446.Extension.SignatureAlgorithmsCert.Error.self) {
            try RFC_8446.Extension.SignatureAlgorithmsCert(binary: Self.emptyVector16)
        }
    }

    @Test
    func `an empty PSK key exchange mode list is refused`() {
        #expect(throws: RFC_8446.Extension.PskKeyExchangeModes.Error.self) {
            try RFC_8446.Extension.PskKeyExchangeModes(binary: [Byte(0)])
        }
    }

    @Test
    func `an empty cookie is refused`() {
        #expect(throws: RFC_8446.Extension.Cookie.Error.self) {
            try RFC_8446.Extension.Cookie(binary: Self.emptyVector16)
        }
    }

    @Test
    func `non-empty lists still parse`() throws {
        _ = try RFC_8446.Extension.SupportedGroups(binary: [0, 2, 0, 0x1D].map { Byte($0) })
        _ = try RFC_8446.Extension.PskKeyExchangeModes(binary: [1, 1].map { Byte($0) })
        _ = try RFC_8446.Extension.Cookie(binary: [0, 1, 0xAB].map { Byte($0) })
    }
}
