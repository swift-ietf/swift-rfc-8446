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

// Fable-448 F-001 regression tests: handshake payload constructors validate
// spec length bounds so serialization is total and non-trapping.

import Binary_Serializable_Primitives
import RFC_8446
import Testing

extension RFC_8446.Handshake.Message {
    @Suite struct `Edge Case` {
        @Test func `init rejects bodies over the uint24 bound`() {
            #expect(throws: RFC_8446.Handshake.Message.Error.bodyTooLong(0x100_0000)) {
                _ = try RFC_8446.Handshake.Message(
                    type: .clientHello,
                    body: [Byte](repeating: Byte(0), count: 0x100_0000)
                )
            }
        }

        @Test func `init accepts a body at the uint24 bound and serializes totally`() throws {
            let message = try RFC_8446.Handshake.Message(
                type: .finished,
                body: [Byte](repeating: Byte(0), count: 0xFF_FFFF)
            )
            var buffer: [Byte] = []
            RFC_8446.Handshake.Message.serialize(message, into: &buffer)
            #expect(buffer.count == 4 + 0xFF_FFFF)
            #expect(buffer[1] == 0xFF && buffer[2] == 0xFF && buffer[3] == 0xFF)
        }
    }
}

extension RFC_8446.Handshake.ClientHello {
    @Suite struct `Edge Case` {
        static let random32 = [Byte](repeating: Byte(7), count: 32)

        @Test func `init rejects out-of-bounds fields`() throws {
            #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidRandomLength(31)) {
                _ = try RFC_8446.Handshake.ClientHello(
                    random: [Byte](repeating: Byte(0), count: 31),
                    cipherSuites: [.aes128GcmSha256],
                    extensions: []
                )
            }
            #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidSessionIDLength(33)) {
                _ = try RFC_8446.Handshake.ClientHello(
                    random: Self.random32,
                    legacySessionID: [Byte](repeating: Byte(0), count: 33),
                    cipherSuites: [.aes128GcmSha256],
                    extensions: []
                )
            }
            #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidCipherSuiteCount(0)) {
                _ = try RFC_8446.Handshake.ClientHello(
                    random: Self.random32,
                    cipherSuites: [],
                    extensions: []
                )
            }
            #expect(throws: RFC_8446.Handshake.ClientHello.Error.invalidCompressionMethodsLength(0)) {
                _ = try RFC_8446.Handshake.ClientHello(
                    random: Self.random32,
                    cipherSuites: [.aes128GcmSha256],
                    legacyCompressionMethods: [],
                    extensions: []
                )
            }
            let fat = try RFC_8446.Extension.Data(
                type: .serverName,
                data: [Byte](repeating: Byte(0), count: 0xFFFF)
            )
            #expect(throws: RFC_8446.Handshake.ClientHello.Error.extensionsTooLong(4 + 0xFFFF)) {
                _ = try RFC_8446.Handshake.ClientHello(
                    random: Self.random32,
                    cipherSuites: [.aes128GcmSha256],
                    extensions: [fat]
                )
            }
        }
    }
}

extension RFC_8446.Handshake.ServerHello {
    @Suite struct `Edge Case` {
        @Test func `init rejects out-of-bounds fields`() throws {
            #expect(throws: RFC_8446.Handshake.ServerHello.Error.invalidRandomLength(31)) {
                _ = try RFC_8446.Handshake.ServerHello(
                    random: [Byte](repeating: Byte(0), count: 31),
                    cipherSuite: .aes128GcmSha256,
                    extensions: []
                )
            }
            #expect(throws: RFC_8446.Handshake.ServerHello.Error.invalidSessionIDEchoLength(33)) {
                _ = try RFC_8446.Handshake.ServerHello(
                    random: [Byte](repeating: Byte(0), count: 32),
                    legacySessionIDEcho: [Byte](repeating: Byte(0), count: 33),
                    cipherSuite: .aes128GcmSha256,
                    extensions: []
                )
            }
        }
    }
}

extension RFC_8446.Handshake.Certificate {
    @Suite struct `Edge Case` {
        @Test func `entry init rejects empty cert_data`() {
            #expect(throws: RFC_8446.Handshake.Certificate.Error.invalidCertificateDataLength(0)) {
                _ = try RFC_8446.Handshake.Certificate.Entry(certificateData: [])
            }
        }

        @Test func `init rejects oversize certificate_request_context`() throws {
            let entry = try RFC_8446.Handshake.Certificate.Entry(certificateData: [Byte(1)])
            #expect(throws: RFC_8446.Handshake.Certificate.Error.invalidContextLength(256)) {
                _ = try RFC_8446.Handshake.Certificate(
                    certificateRequestContext: [Byte](repeating: Byte(0), count: 256),
                    certificateList: [entry]
                )
            }
        }
    }
}

extension RFC_8446.Handshake.CertificateRequest {
    @Suite struct `Edge Case` {
        @Test func `init rejects oversize certificate_request_context`() {
            #expect(throws: RFC_8446.Handshake.CertificateRequest.Error.invalidContextLength(256)) {
                _ = try RFC_8446.Handshake.CertificateRequest(
                    certificateRequestContext: [Byte](repeating: Byte(0), count: 256),
                    extensions: []
                )
            }
        }
    }
}

extension RFC_8446.Handshake.CertificateVerify {
    @Suite struct `Edge Case` {
        @Test func `init rejects signatures over the uint16 bound`() {
            #expect(throws: RFC_8446.Handshake.CertificateVerify.Error.signatureTooLong(0x1_0000)) {
                _ = try RFC_8446.Handshake.CertificateVerify(
                    algorithm: .ed25519,
                    signature: [Byte](repeating: Byte(0), count: 0x1_0000)
                )
            }
        }
    }
}

extension RFC_8446.Handshake.EncryptedExtensions {
    @Suite struct `Edge Case` {
        @Test func `init rejects an oversize extensions block`() throws {
            let fat = try RFC_8446.Extension.Data(
                type: .serverName,
                data: [Byte](repeating: Byte(0), count: 0xFFFF)
            )
            #expect(throws: RFC_8446.Handshake.EncryptedExtensions.Error.extensionsTooLong(4 + 0xFFFF)) {
                _ = try RFC_8446.Handshake.EncryptedExtensions(extensions: [fat])
            }
        }
    }
}

extension RFC_8446.Handshake.NewSessionTicket {
    @Suite struct `Edge Case` {
        @Test func `init rejects oversize nonce and empty ticket`() {
            #expect(throws: RFC_8446.Handshake.NewSessionTicket.Error.invalidNonceLength(256)) {
                _ = try RFC_8446.Handshake.NewSessionTicket(
                    ticketLifetime: 1,
                    ticketAgeAdd: 0,
                    ticketNonce: [Byte](repeating: Byte(0), count: 256),
                    ticket: [Byte(1)]
                )
            }
            #expect(throws: RFC_8446.Handshake.NewSessionTicket.Error.invalidTicketLength(0)) {
                _ = try RFC_8446.Handshake.NewSessionTicket(
                    ticketLifetime: 1,
                    ticketAgeAdd: 0,
                    ticketNonce: [],
                    ticket: []
                )
            }
        }
    }
}

extension RFC_8446.Handshake.Finished {
    @Suite struct `Edge Case` {
        @Test func `init rejects verify_data over the uint24 bound`() {
            #expect(throws: RFC_8446.Handshake.Finished.Error.verifyDataTooLong(0x100_0000)) {
                _ = try RFC_8446.Handshake.Finished(
                    verifyData: [Byte](repeating: Byte(0), count: 0x100_0000)
                )
            }
        }
    }
}
