import Binary_Serializable
import Testing

@testable import RFC_8446

@Suite("RFC 8446 handshake payload round-trips")
struct RFC_8446_HandshakeRoundTrip_Tests {

    static let sampleRandom: [Byte] = (0..<32).map { Byte(UInt8($0)) }

    static let sampleExtensions: [RFC_8446.Extension.Data] = [

        try! RFC_8446.Extension.Data(type: .supportedVersions, data: [Byte(0x03), Byte(0x04)]),

        try! RFC_8446.Extension.Data(type: .cookie, data: [Byte(0xAA), Byte(0xBB), Byte(0xCC)]),
    ]

    @Test
    func `Message envelope round-trips`() throws {
        let message = try RFC_8446.Handshake.Message(
            type: .clientHello,
            body: [Byte(1), Byte(2), Byte(3)]
        )
        let parsed = try RFC_8446.Handshake.Message(binary: message.bytes)
        #expect(parsed == message)
    }

    @Test
    func `ClientHello round-trips`() throws {
        let hello = try RFC_8446.Handshake.ClientHello(
            random: Self.sampleRandom,
            legacySessionID: [Byte(0xDE), Byte(0xAD)],
            cipherSuites: [.aes128GcmSha256, .aes256GcmSha384],
            extensions: Self.sampleExtensions
        )
        #expect(try RFC_8446.Handshake.ClientHello(binary: hello.bytes) == hello)
    }

    @Test
    func `ServerHello round-trips`() throws {
        let hello = try RFC_8446.Handshake.ServerHello(
            random: Self.sampleRandom,
            legacySessionIDEcho: [Byte(0xDE), Byte(0xAD)],
            cipherSuite: .aes128GcmSha256,
            extensions: Self.sampleExtensions
        )
        #expect(try RFC_8446.Handshake.ServerHello(binary: hello.bytes) == hello)
        #expect(hello.isHelloRetryRequest == false)
    }

    @Test
    func `ServerHello with HelloRetryRequest random discriminates`() throws {
        let hrr = try RFC_8446.Handshake.ServerHello(
            random: RFC_8446.Handshake.ServerHello.helloRetryRequestRandom,
            cipherSuite: .aes128GcmSha256,
            extensions: [
                try RFC_8446.Extension.Data(
                    type: .supportedVersions,
                    data: [Byte(0x03), Byte(0x04)]
                )
            ]
        )
        #expect(hrr.isHelloRetryRequest == true)
        let parsed = try RFC_8446.Handshake.ServerHello(binary: hrr.bytes)
        #expect(parsed.isHelloRetryRequest == true)
        #expect(parsed == hrr)
    }

    @Test
    func `EncryptedExtensions round-trips`() throws {
        let ee = try RFC_8446.Handshake.EncryptedExtensions(extensions: Self.sampleExtensions)
        #expect(try RFC_8446.Handshake.EncryptedExtensions(binary: ee.bytes) == ee)
    }

    @Test
    func `Certificate round-trips`() throws {
        let certificate = try RFC_8446.Handshake.Certificate(
            certificateRequestContext: [Byte(0x01)],
            certificateList: [
                try RFC_8446.Handshake.Certificate.Entry(
                    certificateData: [Byte(0xCA), Byte(0xFE)],
                    extensions: [try RFC_8446.Extension.Data(type: .statusRequest, data: [])]
                ),
                try RFC_8446.Handshake.Certificate.Entry(certificateData: [Byte(0xBE), Byte(0xEF)]
                ),
            ]
        )
        #expect(try RFC_8446.Handshake.Certificate(binary: certificate.bytes) == certificate)
    }

    @Test
    func `CertificateRequest round-trips`() throws {
        let request = try RFC_8446.Handshake.CertificateRequest(
            certificateRequestContext: [Byte(0x2A)],
            extensions: Self.sampleExtensions
        )
        #expect(try RFC_8446.Handshake.CertificateRequest(binary: request.bytes) == request)
    }

    @Test
    func `CertificateVerify round-trips`() throws {
        let verify = try RFC_8446.Handshake.CertificateVerify(
            algorithm: .ed25519,
            signature: [Byte(0x01), Byte(0x02), Byte(0x03), Byte(0x04)]
        )
        #expect(try RFC_8446.Handshake.CertificateVerify(binary: verify.bytes) == verify)
    }

    @Test
    func `Finished round-trips`() throws {
        let finished = try RFC_8446.Handshake.Finished(verifyData: Self.sampleRandom)
        #expect(try RFC_8446.Handshake.Finished(binary: finished.bytes) == finished)
    }

    @Test
    func `NewSessionTicket round-trips`() throws {
        let ticket = try RFC_8446.Handshake.NewSessionTicket(
            ticketLifetime: 7200,
            ticketAgeAdd: 0xDEAD_BEEF,
            ticketNonce: [Byte(0x00), Byte(0x01)],
            ticket: [Byte(0xAB), Byte(0xCD), Byte(0xEF)],
            extensions: [RFC_8446.Extension.EarlyData.Ticket(maxEarlyDataSize: 16384).extensionData]
        )
        #expect(try RFC_8446.Handshake.NewSessionTicket(binary: ticket.bytes) == ticket)
    }

    @Test
    func `KeyUpdate round-trips both request values`() throws {
        for request in [RFC_8446.Handshake.KeyUpdate.Request.updateNotRequested, .updateRequested] {
            let update = RFC_8446.Handshake.KeyUpdate(requestUpdate: request)
            #expect(try RFC_8446.Handshake.KeyUpdate(binary: update.bytes) == update)
        }
    }

    @Test
    func `EndOfEarlyData round-trips`() throws {
        let eoed = RFC_8446.Handshake.EndOfEarlyData()
        #expect(try RFC_8446.Handshake.EndOfEarlyData(binary: eoed.bytes) == eoed)
        #expect(eoed.bytes == [])
    }
}
