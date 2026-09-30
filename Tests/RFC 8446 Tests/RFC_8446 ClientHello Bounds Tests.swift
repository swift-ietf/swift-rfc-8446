import Testing

@testable import RFC_8446

@Suite
struct `ClientHello wire bounds` {
    private static func hello(sessionID: Int, suites: Int, compression: Int) -> [Byte] {
        var bytes: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 0, count: 32)
        bytes += [UInt8(sessionID)] + [UInt8](repeating: 0xAA, count: sessionID)
        bytes += [UInt8((suites * 2) >> 8), UInt8((suites * 2) & 0xFF)]
        for _ in 0..<suites { bytes += [0x13, 0x01] }
        bytes += [UInt8(compression)] + [UInt8](repeating: 0, count: compression)
        bytes += [0x00, 0x00]
        return bytes.map { Byte($0) }
    }

    @Test
    func `a well-formed hello parses`() throws {
        let hello = try RFC_8446.Handshake.ClientHello(binary: Self.hello(sessionID: 32, suites: 1, compression: 1))
        #expect(hello.legacySessionID.count == 32)
    }

    @Test
    func `a session id longer than 32 bytes is refused`() {
        #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidSessionIDLength(33)) {
            try RFC_8446.Handshake.ClientHello(binary: Self.hello(sessionID: 33, suites: 1, compression: 1))
        }
    }

    @Test
    func `an empty cipher suite list is refused`() {
        #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidCipherSuiteCount(0)) {
            try RFC_8446.Handshake.ClientHello(binary: Self.hello(sessionID: 0, suites: 0, compression: 1))
        }
    }

    @Test
    func `an empty compression method list is refused`() {
        #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidCompressionMethodsLength(0)) {
            try RFC_8446.Handshake.ClientHello(binary: Self.hello(sessionID: 0, suites: 1, compression: 0))
        }
    }
}
