// ===----------------------------------------------------------------------===//
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of project contributors
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

import Binary_Serializable_Primitives
import Testing

@testable import RFC_8446

@Suite("RFC 8448 Section 3 byte-exact message parsing")
struct RFC_8446_RFC8448_Message_Tests {

    // MARK: - ClientHello

    @Test
    func `ClientHello parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.clientHello)
        #expect(message.type == .clientHello)

        let hello = try RFC_8446.Handshake.ClientHello(binary: message.body)

        // Fields.
        #expect(hello.legacyVersion == .tls1_2)
        #expect(hello.random == hex("""
            cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
            ec 18 a2 ef 62 83 02 4d ec e7
            """))
        #expect(hello.legacySessionID == [])
        #expect(hello.cipherSuites == [.aes128GcmSha256, .chacha20Poly1305Sha256, .aes256GcmSha384])
        #expect(hello.legacyCompressionMethods == [Byte(0)])

        // Re-serialization is byte-identical.
        #expect(hello.bytes == message.body)
        #expect(hello.message.bytes == RFC8448.clientHello)
    }

    @Test
    func `ClientHello key_share extension parses into typed KeyShare`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.clientHello)
        let hello = try RFC_8446.Handshake.ClientHello(binary: message.body)

        let keyShareExt = try #require(hello.extensions.first { $0.type == .keyShare })
        let keyShare = try RFC_8446.Extension.KeyShare.ClientHello(binary: keyShareExt.data)

        #expect(keyShare.clientShares.count == 1)
        #expect(keyShare.clientShares[0].group == .x25519)
        #expect(keyShare.clientShares[0].keyExchange == hex("""
            99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c
            ae 4d 54 13 69 1e 52 9a af 2c
            """))
        #expect(keyShare.bytes == keyShareExt.data)
    }

    @Test
    func `ClientHello supported_versions offers TLS 1.3`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.clientHello)
        let hello = try RFC_8446.Handshake.ClientHello(binary: message.body)

        let ext = try #require(hello.extensions.first { $0.type == .supportedVersions })
        let versions = try RFC_8446.Extension.SupportedVersions.ClientHello(binary: ext.data)
        #expect(versions.versions == [.tls1_3])
        #expect(versions.bytes == ext.data)
    }

    // MARK: - ServerHello

    @Test
    func `ServerHello parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.serverHello)
        #expect(message.type == .serverHello)

        let hello = try RFC_8446.Handshake.ServerHello(binary: message.body)
        #expect(hello.legacyVersion == .tls1_2)
        #expect(hello.cipherSuite == .aes128GcmSha256)
        #expect(hello.legacyCompressionMethod == 0)
        #expect(hello.isHelloRetryRequest == false)

        #expect(hello.bytes == message.body)
        #expect(hello.message.bytes == RFC8448.serverHello)
    }

    @Test
    func `ServerHello key_share and supported_versions parse`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.serverHello)
        let hello = try RFC_8446.Handshake.ServerHello(binary: message.body)

        let keyShareExt = try #require(hello.extensions.first { $0.type == .keyShare })
        let keyShare = try RFC_8446.Extension.KeyShare.ServerHello(binary: keyShareExt.data)
        #expect(keyShare.serverShare.group == .x25519)
        #expect(keyShare.bytes == keyShareExt.data)

        let versionExt = try #require(hello.extensions.first { $0.type == .supportedVersions })
        let version = try RFC_8446.Extension.SupportedVersions.ServerHello(binary: versionExt.data)
        #expect(version.selectedVersion == .tls1_3)
        #expect(version.bytes == versionExt.data)
    }

    // MARK: - EncryptedExtensions

    @Test
    func `EncryptedExtensions parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.encryptedExtensions)
        #expect(message.type == .encryptedExtensions)

        let ee = try RFC_8446.Handshake.EncryptedExtensions(binary: message.body)
        #expect(ee.extensions.contains { $0.type == .supportedGroups })
        #expect(ee.extensions.contains { $0.type == .serverName })

        #expect(ee.bytes == message.body)
        #expect(ee.message.bytes == RFC8448.encryptedExtensions)
    }

    // MARK: - Certificate

    @Test
    func `Certificate parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.certificate)
        #expect(message.type == .certificate)

        let certificate = try RFC_8446.Handshake.Certificate(binary: message.body)
        #expect(certificate.certificateRequestContext == [])
        #expect(certificate.certificateList.count == 1)
        #expect(certificate.certificateList[0].certificateData.count == 432)
        #expect(certificate.certificateList[0].extensions == [])

        #expect(certificate.bytes == message.body)
        #expect(certificate.message.bytes == RFC8448.certificate)
    }

    // MARK: - CertificateVerify

    @Test
    func `CertificateVerify parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.certificateVerify)
        #expect(message.type == .certificateVerify)

        let verify = try RFC_8446.Handshake.CertificateVerify(binary: message.body)
        #expect(verify.algorithm == .rsaPssRsaeSha256)
        #expect(verify.signature.count == 128)

        #expect(verify.bytes == message.body)
        #expect(verify.message.bytes == RFC8448.certificateVerify)
    }

    // MARK: - Finished

    @Test
    func `Server Finished parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.serverFinished)
        #expect(message.type == .finished)

        let finished = RFC_8446.Handshake.Finished(binary: message.body)
        #expect(finished.verifyData == RFC8448.serverFinishedVerifyData)

        #expect(finished.bytes == message.body)
        #expect(finished.message.bytes == RFC8448.serverFinished)
    }

    // MARK: - NewSessionTicket

    @Test
    func `NewSessionTicket parses byte-exactly and re-serializes`() throws {
        let message = try RFC_8446.Handshake.Message(binary: RFC8448.newSessionTicket)
        #expect(message.type == .newSessionTicket)

        let ticket = try RFC_8446.Handshake.NewSessionTicket(binary: message.body)
        #expect(ticket.ticketLifetime == 30)
        #expect(ticket.ticketNonce == [Byte(0), Byte(0)])

        // Its sole extension is early_data with max_early_data_size = 1024.
        let earlyExt = try #require(ticket.extensions.first { $0.type == .earlyData })
        let early = try RFC_8446.Extension.EarlyData.Ticket(binary: earlyExt.data)
        #expect(early.maxEarlyDataSize == 1024)

        #expect(ticket.bytes == message.body)
        #expect(ticket.message.bytes == RFC8448.newSessionTicket)
    }
}
