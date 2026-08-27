import Binary_Serializable
import Testing

@testable import RFC_8446

@Suite("RFC 8446 extension payload round-trips")
struct RFC_8446_ExtensionRoundTrip_Tests {

    @Test
    func `Extension.Data envelope round-trips`() throws {
        let ext = try RFC_8446.Extension.Data(type: .cookie, data: [Byte(1), Byte(2), Byte(3)])
        #expect(try RFC_8446.Extension.Data(binary: ext.bytes) == ext)
    }

    @Test
    func `SupportedGroups round-trips`() throws {
        let value = try RFC_8446.Extension.SupportedGroups(namedGroupList: [
            .x25519, .secp256r1, .x448,
        ])
        #expect(try RFC_8446.Extension.SupportedGroups(binary: value.bytes) == value)
        #expect(value.extensionData.type == .supportedGroups)
    }

    @Test
    func `SignatureAlgorithms round-trips`() throws {
        let value = try RFC_8446.Extension.SignatureAlgorithms(
            supportedSignatureAlgorithms: [.ecdsaSecp256r1Sha256, .rsaPssRsaeSha256, .ed25519]
        )
        #expect(try RFC_8446.Extension.SignatureAlgorithms(binary: value.bytes) == value)
        #expect(value.extensionData.type == .signatureAlgorithms)
    }

    @Test
    func `SignatureAlgorithmsCert round-trips`() throws {
        let value = try RFC_8446.Extension.SignatureAlgorithmsCert(
            supportedSignatureAlgorithms: [.rsaPkcs1Sha256, .ed448]
        )
        #expect(try RFC_8446.Extension.SignatureAlgorithmsCert(binary: value.bytes) == value)
        #expect(value.extensionData.type == .signatureAlgorithmsCert)
    }

    @Test
    func `Cookie round-trips`() throws {
        let value = try RFC_8446.Extension.Cookie(cookie: [Byte(0xC0), Byte(0x0C), Byte(0x1E)])
        #expect(try RFC_8446.Extension.Cookie(binary: value.bytes) == value)
        #expect(value.extensionData.type == .cookie)
    }

    @Test
    func `Padding round-trips`() throws {
        let value = try RFC_8446.Extension.Padding(length: 8)
        #expect(try RFC_8446.Extension.Padding(binary: value.bytes) == value)
        #expect(value.padding == Array(repeating: Byte(0), count: 8))
        #expect(value.extensionData.type == .padding)
    }

    @Test
    func `PskKeyExchangeModes round-trips`() throws {
        let value = try RFC_8446.Extension.PskKeyExchangeModes(keModes: [.pskDheKe, .pskKe])
        #expect(try RFC_8446.Extension.PskKeyExchangeModes(binary: value.bytes) == value)
        #expect(value.extensionData.type == .pskKeyExchangeModes)
    }

    @Test
    func `KeyShare ClientHello round-trips`() throws {
        let value = try RFC_8446.Extension.KeyShare.ClientHello(clientShares: [
            try RFC_8446.Extension.KeyShare.Entry(
                group: .x25519,
                keyExchange: Array(repeating: Byte(0xAB), count: 32)
            ),
            try RFC_8446.Extension.KeyShare.Entry(
                group: .secp256r1,
                keyExchange: Array(repeating: Byte(0xCD), count: 65)
            ),
        ])
        #expect(try RFC_8446.Extension.KeyShare.ClientHello(binary: value.bytes) == value)
        #expect(value.extensionData.type == .keyShare)
    }

    @Test
    func `KeyShare ServerHello round-trips`() throws {
        let value = RFC_8446.Extension.KeyShare.ServerHello(
            serverShare: try RFC_8446.Extension.KeyShare.Entry(
                group: .x25519,
                keyExchange: Array(repeating: Byte(0x11), count: 32)
            )
        )
        #expect(try RFC_8446.Extension.KeyShare.ServerHello(binary: value.bytes) == value)
    }

    @Test
    func `KeyShare HelloRetryRequest round-trips`() throws {
        let value = RFC_8446.Extension.KeyShare.HelloRetryRequest(selectedGroup: .secp384r1)
        #expect(try RFC_8446.Extension.KeyShare.HelloRetryRequest(binary: value.bytes) == value)
    }

    @Test
    func `SupportedVersions ClientHello round-trips`() throws {
        let value = try RFC_8446.Extension.SupportedVersions.ClientHello(versions: [
            .tls1_3, .tls1_2,
        ])
        #expect(try RFC_8446.Extension.SupportedVersions.ClientHello(binary: value.bytes) == value)
        #expect(value.extensionData.type == .supportedVersions)
    }

    @Test
    func `SupportedVersions ServerHello round-trips`() throws {
        let value = RFC_8446.Extension.SupportedVersions.ServerHello(selectedVersion: .tls1_3)
        #expect(try RFC_8446.Extension.SupportedVersions.ServerHello(binary: value.bytes) == value)
    }

    @Test
    func `PreSharedKey OfferedPsks round-trips`() throws {
        let value = try RFC_8446.Extension.PreSharedKey.OfferedPsks(
            identities: [
                try RFC_8446.Extension.PreSharedKey.Identity(
                    identity: [Byte(0x01), Byte(0x02)],
                    obfuscatedTicketAge: 12345
                ),
                try RFC_8446.Extension.PreSharedKey.Identity(
                    identity: [Byte(0x03)],
                    obfuscatedTicketAge: 0
                ),
            ],
            binders: [
                Array(repeating: Byte(0xAA), count: 32),
                Array(repeating: Byte(0xBB), count: 48),
            ]
        )
        #expect(try RFC_8446.Extension.PreSharedKey.OfferedPsks(binary: value.bytes) == value)
        #expect(value.extensionData.type == .preSharedKey)
    }

    @Test
    func `PreSharedKey ServerHello round-trips`() throws {
        let value = RFC_8446.Extension.PreSharedKey.ServerHello(selectedIdentity: 0)
        #expect(try RFC_8446.Extension.PreSharedKey.ServerHello(binary: value.bytes) == value)
    }

    @Test
    func `EarlyData Indication round-trips`() throws {
        let value = RFC_8446.Extension.EarlyData.Indication()
        #expect(try RFC_8446.Extension.EarlyData.Indication(binary: value.bytes) == value)
        #expect(value.bytes == [])
    }

    @Test
    func `EarlyData Ticket round-trips`() throws {
        let value = RFC_8446.Extension.EarlyData.Ticket(maxEarlyDataSize: 1024)
        #expect(try RFC_8446.Extension.EarlyData.Ticket(binary: value.bytes) == value)
        #expect(value.extensionData.type == .earlyData)
    }

    @Test
    func `CertificateAuthorities round-trips`() throws {
        let value = try RFC_8446.Extension.CertificateAuthorities(authorities: [
            [Byte(0x30), Byte(0x0E)],
            [Byte(0x30), Byte(0x10), Byte(0x20)],
        ])
        #expect(try RFC_8446.Extension.CertificateAuthorities(binary: value.bytes) == value)
        #expect(value.extensionData.type == .certificateAuthorities)
    }

    @Test
    func `OidFilters round-trips`() throws {
        let value = try RFC_8446.Extension.OidFilters(filters: [
            try RFC_8446.Extension.OidFilters.Filter(
                certificateExtensionOID: [Byte(0x55), Byte(0x1D), Byte(0x0F)],
                certificateExtensionValues: [Byte(0x03), Byte(0x02), Byte(0x05), Byte(0xA0)]
            )
        ])
        #expect(try RFC_8446.Extension.OidFilters(binary: value.bytes) == value)
        #expect(value.extensionData.type == .oidFilters)
    }

    @Test
    func `PostHandshakeAuth round-trips`() throws {
        let value = RFC_8446.Extension.PostHandshakeAuth()
        #expect(try RFC_8446.Extension.PostHandshakeAuth(binary: value.bytes) == value)
        #expect(value.bytes == [])
    }
}
