import Testing

@testable import RFC_8446

@Suite
struct `Message wire bounds` {
    private static func bytes(_ values: [UInt8]) -> [Byte] { values.map { Byte($0) } }

    @Test
    func `an empty certificate authority name is refused`() {
        #expect(throws: RFC_8446.Extension.CertificateAuthorities.Error.self) {
            try RFC_8446.Extension.CertificateAuthorities(binary: Self.bytes([0, 2, 0, 0]))
        }
    }

    @Test
    func `an empty session ticket is refused`() {
        let wire: [UInt8] = [0, 0, 0, 1] + [0, 0, 0, 2] + [0] + [0, 0] + [0, 0]
        #expect(throws: RFC_8446.Handshake.NewSessionTicket.Error.self) {
            try RFC_8446.Handshake.NewSessionTicket(binary: Self.bytes(wire))
        }
    }

    @Test
    func `a server session id echo longer than 32 bytes is refused`() {
        let wire: [UInt8] = [3, 3] + [UInt8](repeating: 0, count: 32) + [33] + [UInt8](repeating: 1, count: 33)
            + [0x13, 0x01] + [0] + [0, 0]
        #expect(throws: RFC_8446.Handshake.ServerHello.Error.self) {
            try RFC_8446.Handshake.ServerHello(binary: Self.bytes(wire))
        }
    }

    @Test
    func `well-formed messages still parse`() throws {
        _ = try RFC_8446.Extension.CertificateAuthorities(binary: Self.bytes([0, 3, 0, 1, 0x30]))
        _ = try RFC_8446.Handshake.NewSessionTicket(
            binary: Self.bytes([0, 0, 0, 1] + [0, 0, 0, 2] + [0] + [0, 1, 0xAB] + [0, 0])
        )
        _ = try RFC_8446.Handshake.ServerHello(
            binary: Self.bytes([3, 3] + [UInt8](repeating: 0, count: 32) + [32] + [UInt8](repeating: 1, count: 32)
                + [0x13, 0x01] + [0] + [0, 0])
        )
    }
}
