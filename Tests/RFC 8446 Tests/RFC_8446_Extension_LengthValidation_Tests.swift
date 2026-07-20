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

// Fable-448 F-001 regression tests: extension payload constructors validate
// spec length bounds so serialization is total and non-trapping.

import Binary_Serializable_Primitives
import RFC_8446
import Testing

extension RFC_8446.Extension.Data {
    @Suite struct `Edge Case` {
        @Test func `init rejects extension_data over the uint16 bound`() {
            #expect(throws: RFC_8446.Extension.Data.Error.dataTooLong(0x1_0000)) {
                _ = try RFC_8446.Extension.Data(
                    type: .serverName,
                    data: [Byte](repeating: Byte(0), count: 0x1_0000)
                )
            }
        }

        @Test func `init accepts extension_data at the uint16 bound and serializes totally`() throws {
            let ext = try RFC_8446.Extension.Data(
                type: .serverName,
                data: [Byte](repeating: Byte(0xAB), count: 0xFFFF)
            )
            var buffer: [Byte] = []
            RFC_8446.Extension.Data.serialize(ext, into: &buffer)
            #expect(buffer.count == 4 + 0xFFFF)
            #expect(buffer[2] == 0xFF && buffer[3] == 0xFF)
        }
    }
}

extension RFC_8446.Extension.Cookie {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty and oversize cookies`() {
            #expect(throws: RFC_8446.Extension.Cookie.Error.invalidCookieLength(0)) {
                _ = try RFC_8446.Extension.Cookie(cookie: [])
            }
            #expect(throws: RFC_8446.Extension.Cookie.Error.invalidCookieLength(0xFFFE)) {
                _ = try RFC_8446.Extension.Cookie(cookie: [Byte](repeating: Byte(0), count: 0xFFFE))
            }
        }
    }
}

extension RFC_8446.Extension.KeyShare.Entry {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty key_exchange`() {
            #expect(throws: RFC_8446.Extension.KeyShare.Error.invalidKeyExchangeLength(0)) {
                _ = try RFC_8446.Extension.KeyShare.Entry(group: .x25519, keyExchange: [])
            }
        }
    }
}

extension RFC_8446.Extension.KeyShare.ClientHello {
    @Suite struct `Edge Case` {
        @Test func `init rejects an oversize client_shares block`() throws {
            let big = try RFC_8446.Extension.KeyShare.Entry(
                group: .x25519,
                keyExchange: [Byte](repeating: Byte(0), count: 40_000)
            )
            #expect(throws: RFC_8446.Extension.KeyShare.Error.clientSharesTooLong(2 * 40_004)) {
                _ = try RFC_8446.Extension.KeyShare.ClientHello(clientShares: [big, big])
            }
        }
    }
}

extension RFC_8446.Extension.CertificateAuthorities {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty authorities and oversize blocks`() {
            #expect(throws: RFC_8446.Extension.CertificateAuthorities.Error.invalidAuthorityLength(0)) {
                _ = try RFC_8446.Extension.CertificateAuthorities(authorities: [[]])
            }
            let big = [Byte](repeating: Byte(0), count: 40_000)
            #expect(throws: RFC_8446.Extension.CertificateAuthorities.Error.authoritiesTooLong(2 * 40_002)) {
                _ = try RFC_8446.Extension.CertificateAuthorities(authorities: [big, big])
            }
        }
    }
}

extension RFC_8446.Extension.OidFilters {
    @Suite struct `Edge Case` {
        @Test func `filter init rejects empty OID and oversize values`() {
            #expect(throws: RFC_8446.Extension.OidFilters.Error.invalidOIDLength(0)) {
                _ = try RFC_8446.Extension.OidFilters.Filter(
                    certificateExtensionOID: [],
                    certificateExtensionValues: []
                )
            }
            #expect(throws: RFC_8446.Extension.OidFilters.Error.valuesTooLong(0x1_0000)) {
                _ = try RFC_8446.Extension.OidFilters.Filter(
                    certificateExtensionOID: [Byte(0x55)],
                    certificateExtensionValues: [Byte](repeating: Byte(0), count: 0x1_0000)
                )
            }
        }

        @Test func `init rejects an oversize filters block`() throws {
            let fat = try RFC_8446.Extension.OidFilters.Filter(
                certificateExtensionOID: [Byte(0x55)],
                certificateExtensionValues: [Byte](repeating: Byte(0), count: 40_000)
            )
            #expect(throws: RFC_8446.Extension.OidFilters.Error.filtersTooLong(2 * 40_004)) {
                _ = try RFC_8446.Extension.OidFilters(filters: [fat, fat])
            }
        }
    }
}

extension RFC_8446.Extension.PreSharedKey.OfferedPsks {
    @Suite struct `Edge Case` {
        @Test func `identity init rejects empty identity`() {
            #expect(throws: RFC_8446.Extension.PreSharedKey.Error.invalidIdentityLength(0)) {
                _ = try RFC_8446.Extension.PreSharedKey.Identity(identity: [], obfuscatedTicketAge: 0)
            }
        }

        @Test func `init rejects undersize binders and oversize payloads`() throws {
            let identity = try RFC_8446.Extension.PreSharedKey.Identity(
                identity: [Byte(1)],
                obfuscatedTicketAge: 0
            )
            #expect(throws: RFC_8446.Extension.PreSharedKey.Error.invalidBinderLength(31)) {
                _ = try RFC_8446.Extension.PreSharedKey.OfferedPsks(
                    identities: [identity],
                    binders: [[Byte](repeating: Byte(0), count: 31)]
                )
            }
            let bigIdentity = try RFC_8446.Extension.PreSharedKey.Identity(
                identity: [Byte](repeating: Byte(0), count: 0xFFFF),
                obfuscatedTicketAge: 0
            )
            let binder = [Byte](repeating: Byte(0), count: 32)
            #expect(throws: RFC_8446.Extension.PreSharedKey.Error.self) {
                _ = try RFC_8446.Extension.PreSharedKey.OfferedPsks(
                    identities: [bigIdentity],
                    binders: [binder]
                )
            }
        }
    }
}

extension RFC_8446.Extension.PskKeyExchangeModes {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty and oversize mode lists`() {
            #expect(throws: RFC_8446.Extension.PskKeyExchangeModes.Error.invalidModeCount(0)) {
                _ = try RFC_8446.Extension.PskKeyExchangeModes(keModes: [])
            }
            #expect(throws: RFC_8446.Extension.PskKeyExchangeModes.Error.invalidModeCount(256)) {
                _ = try RFC_8446.Extension.PskKeyExchangeModes(
                    keModes: Array(repeating: .pskDheKe, count: 256)
                )
            }
        }
    }
}

extension RFC_8446.Extension.SupportedVersions.ClientHello {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty and oversize version lists`() {
            #expect(throws: RFC_8446.Extension.SupportedVersions.Error.invalidVersionCount(0)) {
                _ = try RFC_8446.Extension.SupportedVersions.ClientHello(versions: [])
            }
            #expect(throws: RFC_8446.Extension.SupportedVersions.Error.invalidVersionCount(128)) {
                _ = try RFC_8446.Extension.SupportedVersions.ClientHello(
                    versions: Array(repeating: .tls1_3, count: 128)
                )
            }
        }
    }
}

extension RFC_8446.Extension.SupportedGroups {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty and oversize group lists`() {
            #expect(throws: RFC_8446.Extension.SupportedGroups.Error.invalidGroupCount(0)) {
                _ = try RFC_8446.Extension.SupportedGroups(namedGroupList: [])
            }
            #expect(throws: RFC_8446.Extension.SupportedGroups.Error.invalidGroupCount(32767)) {
                _ = try RFC_8446.Extension.SupportedGroups(
                    namedGroupList: Array(repeating: .x25519, count: 32767)
                )
            }
        }
    }
}

extension RFC_8446.Extension.SignatureAlgorithms {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty and oversize algorithm lists`() {
            #expect(throws: RFC_8446.Extension.SignatureAlgorithms.Error.invalidAlgorithmCount(0)) {
                _ = try RFC_8446.Extension.SignatureAlgorithms(supportedSignatureAlgorithms: [])
            }
            #expect(throws: RFC_8446.Extension.SignatureAlgorithms.Error.invalidAlgorithmCount(32767)) {
                _ = try RFC_8446.Extension.SignatureAlgorithms(
                    supportedSignatureAlgorithms: Array(repeating: .ed25519, count: 32767)
                )
            }
        }
    }
}

extension RFC_8446.Extension.SignatureAlgorithmsCert {
    @Suite struct `Edge Case` {
        @Test func `init rejects empty and oversize algorithm lists`() {
            #expect(throws: RFC_8446.Extension.SignatureAlgorithmsCert.Error.invalidAlgorithmCount(0)) {
                _ = try RFC_8446.Extension.SignatureAlgorithmsCert(supportedSignatureAlgorithms: [])
            }
        }
    }
}

extension RFC_8446.Extension.Padding {
    @Suite struct `Edge Case` {
        @Test func `init rejects negative and oversize padding lengths`() {
            #expect(throws: RFC_8446.Extension.Padding.Error.invalidPaddingLength(-1)) {
                _ = try RFC_8446.Extension.Padding(length: -1)
            }
            #expect(throws: RFC_8446.Extension.Padding.Error.invalidPaddingLength(0x1_0000)) {
                _ = try RFC_8446.Extension.Padding(
                    padding: [Byte](repeating: Byte(0), count: 0x1_0000)
                )
            }
        }
    }
}
