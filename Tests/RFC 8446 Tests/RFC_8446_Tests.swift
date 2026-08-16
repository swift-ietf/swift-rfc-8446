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

import Testing

@testable import RFC_8446

@Suite("RFC 8446 TLS 1.3 Tests")
struct RFC8446Tests {

    @Suite("Protocol Version Tests")
    struct ProtocolVersionTests {
        @Test
        func `TLS version values`() {
            #expect(RFC_8446.ProtocolVersion.tls1_0.rawValue == 0x0301)
            #expect(RFC_8446.ProtocolVersion.tls1_1.rawValue == 0x0302)
            #expect(RFC_8446.ProtocolVersion.tls1_2.rawValue == 0x0303)
            #expect(RFC_8446.ProtocolVersion.tls1_3.rawValue == 0x0304)
        }

        @Test
        func `Legacy version is TLS 1.2`() {
            #expect(RFC_8446.ProtocolVersion.legacy == .tls1_2)
        }

        @Test
        func `Version components`() {
            let v = RFC_8446.ProtocolVersion.tls1_3
            #expect(v.major == 3)
            #expect(v.minor == 4)
        }

        @Test
        func `Versions are comparable`() {
            #expect(RFC_8446.ProtocolVersion.tls1_2 < RFC_8446.ProtocolVersion.tls1_3)
        }
    }

    @Suite("Content Type Tests")
    struct ContentTypeTests {
        @Test
        func `Content type values`() {
            #expect(RFC_8446.ContentType.invalid.rawValue == 0)
            #expect(RFC_8446.ContentType.changeCipherSpec.rawValue == 20)
            #expect(RFC_8446.ContentType.alert.rawValue == 21)
            #expect(RFC_8446.ContentType.handshake.rawValue == 22)
            #expect(RFC_8446.ContentType.applicationData.rawValue == 23)
        }
    }

    @Suite("Record Tests")
    struct RecordTests {
        @Test
        func `Create TLS record`() throws {
            let record = try RFC_8446.Record(
                contentType: .handshake,
                fragment: [1, 2, 3, 4]
            )

            #expect(record.contentType == .handshake)
            #expect(record.legacyVersion == .legacy)
            #expect(record.fragment == [1, 2, 3, 4])
        }

        @Test
        func `Serialize record`() throws {
            let record = try RFC_8446.Record(
                contentType: .applicationData,
                fragment: [0x01, 0x02, 0x03]
            )

            var buffer: [Byte] = []
            RFC_8446.Record.serialize(record, into: &buffer)

            #expect(buffer.count == 8)  // 5 header + 3 data
            #expect(buffer[0] == 23)  // application_data
            #expect(buffer[1] == 0x03)  // TLS 1.2 high byte
            #expect(buffer[2] == 0x03)  // TLS 1.2 low byte
            #expect(buffer[3] == 0x00)  // length high byte
            #expect(buffer[4] == 0x03)  // length low byte
        }

        @Test
        func `Parse record`() throws {
            let bytes: [Byte] = [
                22,  // handshake
                0x03, 0x03,  // TLS 1.2
                0x00, 0x04,  // length = 4
                1, 2, 3, 4,  // data
            ]

            let record = try RFC_8446.Record(binary: bytes)

            #expect(record.contentType == .handshake)
            #expect(record.legacyVersion == .tls1_2)
            #expect(record.fragment == [1, 2, 3, 4])
        }

        @Test
        func `Reject oversized fragment`() {
            let largeFragment: [Byte] = Array(repeating: Byte(0), count: 16385)

            #expect(throws: RFC_8446.Record.Error.self) {
                try RFC_8446.Record(contentType: .applicationData, fragment: largeFragment)
            }
        }

        @Test
        func `Record limits`() {
            #expect(RFC_8446.Record.Limits.maxPlaintextLength == 16384)
            #expect(RFC_8446.Record.Limits.maxCiphertextLength == 16640)
            #expect(RFC_8446.Record.Limits.headerSize == 5)
        }
    }

    @Suite("Cipher Suite Tests")
    struct CipherSuiteTests {
        @Test
        func `TLS 1.3 cipher suite values`() {
            #expect(RFC_8446.CipherSuite.aes128GcmSha256.rawValue == 0x1301)
            #expect(RFC_8446.CipherSuite.aes256GcmSha384.rawValue == 0x1302)
            #expect(RFC_8446.CipherSuite.chacha20Poly1305Sha256.rawValue == 0x1303)
        }

        @Test
        func `Cipher suite classification`() {
            #expect(RFC_8446.CipherSuite.aes128GcmSha256.isTLS13 == true)
            #expect(RFC_8446.CipherSuite(rawValue: 0x002F).isTLS13 == false)
        }

        @Test
        func `Cipher suite properties`() {
            let cs = RFC_8446.CipherSuite.aes256GcmSha384
            #expect(cs.aeadAlgorithm == "AES-256-GCM")
            #expect(cs.hashAlgorithm == "SHA-384")
            #expect(cs.keyLength == 32)
        }
    }

    @Suite("Alert Tests")
    struct AlertTests {
        @Test
        func `Alert level values`() {
            #expect(RFC_8446.Alert.Level.warning.rawValue == 1)
            #expect(RFC_8446.Alert.Level.fatal.rawValue == 2)
        }

        @Test
        func `Alert description values`() {
            #expect(RFC_8446.Alert.Description.closeNotify.rawValue == 0)
            #expect(RFC_8446.Alert.Description.handshakeFailure.rawValue == 40)
            #expect(RFC_8446.Alert.Description.noApplicationProtocol.rawValue == 120)
        }

        @Test
        func `Create fatal alert`() {
            let alert = RFC_8446.Alert.fatal(.handshakeFailure)
            #expect(alert.level == .fatal)
            #expect(alert.alertDescription == .handshakeFailure)
        }

        @Test
        func `Serialize alert`() {
            let alert = RFC_8446.Alert.closeNotify

            var buffer: [Byte] = []
            RFC_8446.Alert.serialize(alert, into: &buffer)

            #expect(buffer.count == 2)
            #expect(buffer[0] == 1)  // warning
            #expect(buffer[1] == 0)  // close_notify
        }
    }

    @Suite("Handshake Tests")
    struct HandshakeTests {
        @Test
        func `Handshake message type values`() {
            #expect(RFC_8446.Handshake.MessageType.clientHello.rawValue == 1)
            #expect(RFC_8446.Handshake.MessageType.serverHello.rawValue == 2)
            #expect(RFC_8446.Handshake.MessageType.certificate.rawValue == 11)
            #expect(RFC_8446.Handshake.MessageType.finished.rawValue == 20)
        }

        @Test
        func `Serialize handshake message`() throws {
            let message = try RFC_8446.Handshake.Message(
                type: .clientHello,
                body: [1, 2, 3, 4, 5]
            )

            var buffer: [Byte] = []
            RFC_8446.Handshake.Message.serialize(message, into: &buffer)

            #expect(buffer.count == 9)  // 1 type + 3 length + 5 body
            #expect(buffer[0] == 1)  // client_hello
            #expect(buffer[1] == 0)  // length high
            #expect(buffer[2] == 0)  // length mid
            #expect(buffer[3] == 5)  // length low
        }
    }

    @Suite("Extension Tests")
    struct ExtensionTests {
        @Test
        func `Extension type values`() {
            #expect(RFC_8446.Extension.ExtensionType.serverName.rawValue == 0)
            #expect(RFC_8446.Extension.ExtensionType.supportedGroups.rawValue == 10)
            #expect(RFC_8446.Extension.ExtensionType.signatureAlgorithms.rawValue == 13)
            #expect(RFC_8446.Extension.ExtensionType.alpn.rawValue == 16)
            #expect(RFC_8446.Extension.ExtensionType.supportedVersions.rawValue == 43)
            #expect(RFC_8446.Extension.ExtensionType.keyShare.rawValue == 51)
        }

        @Test
        func `Named group values`() {
            #expect(RFC_8446.Extension.NamedGroup.x25519.rawValue == 0x001D)
            #expect(RFC_8446.Extension.NamedGroup.secp256r1.rawValue == 0x0017)
        }

        @Test
        func `Signature scheme values`() {
            #expect(RFC_8446.Extension.SignatureScheme.ed25519.rawValue == 0x0807)
            #expect(RFC_8446.Extension.SignatureScheme.rsaPssRsaeSha256.rawValue == 0x0804)
        }

        @Test
        func `Serialize extension`() throws {
            let ext = try RFC_8446.Extension.Data(
                type: .serverName,
                data: [0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]  // "hello"
            )

            var buffer: [Byte] = []
            RFC_8446.Extension.Data.serialize(ext, into: &buffer)

            #expect(buffer.count == 11)  // 2 type + 2 length + 7 data
            #expect(buffer[0] == 0)  // type high
            #expect(buffer[1] == 0)  // type low (server_name = 0)
        }
    }
}
