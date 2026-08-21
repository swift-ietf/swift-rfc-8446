import RFC_8446
import RFC_8446_Standard_Library_Integration
import Testing

@Suite("RFC 8446 Handshake.Message UInt8 forwarder")
struct RFC_8446_Handshake_Message_UInt8_Tests {
    @Test
    func `forwarder agrees with primary byte-domain construction`() throws {
        let uint8Body: [UInt8] = [1, 2, 3, 4, 5]
        let message = try RFC_8446.Handshake.Message(type: .clientHello, body: uint8Body)
        #expect(message.type == .clientHello)
        #expect(message.body.count == 5)

        let byteBody: [Byte] = uint8Body.map(Byte.init)
        let primaryMessage = try RFC_8446.Handshake.Message(type: .clientHello, body: byteBody)
        #expect(message == primaryMessage)
    }

    @Test
    func `forwarder serializes identically to byte-domain primary`() throws {
        let uint8Body: [UInt8] = [1, 2, 3, 4, 5]
        let message = try RFC_8446.Handshake.Message(type: .clientHello, body: uint8Body)

        var buffer: [Byte] = []
        RFC_8446.Handshake.Message.serialize(message, into: &buffer)

        #expect(buffer.count == 9)
        #expect(buffer[0] == 1)
        #expect(buffer[1] == 0)
        #expect(buffer[2] == 0)
        #expect(buffer[3] == 5)
    }
}
