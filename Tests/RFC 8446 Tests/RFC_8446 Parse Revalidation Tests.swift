import Binary
import RFC_8446
import Testing

extension `RFC_8446.Extension.KeyShare.ClientHello Tests` {
    @Suite struct `Parse` {
        @Test func `parse rejects an empty key_exchange`() {
            #expect(throws: RFC_8446.Extension.KeyShare.Error.invalidKeyExchangeLength(0)) {
                _ = try RFC_8446.Extension.KeyShare.ClientHello(
                    binary: [Byte(0), Byte(4), Byte(0), Byte(0x1D), Byte(0), Byte(0)]
                )
            }
        }
    }
}

enum `RFC_8446.Extension.KeyShare.ServerHello Tests` {}

extension `RFC_8446.Extension.KeyShare.ServerHello Tests` {
    @Suite struct `Parse` {
        @Test func `parse rejects an empty key_exchange`() {
            #expect(throws: RFC_8446.Extension.KeyShare.Error.invalidKeyExchangeLength(0)) {
                _ = try RFC_8446.Extension.KeyShare.ServerHello(
                    binary: [Byte(0), Byte(0x1D), Byte(0), Byte(0)]
                )
            }
        }
    }
}

extension `RFC_8446.Handshake.Certificate Tests` {
    @Suite struct `Parse` {
        @Test func `parse rejects an empty cert_data`() {
            #expect(throws: RFC_8446.Handshake.Certificate.Error.invalidCertificateDataLength(0)) {
                _ = try RFC_8446.Handshake.Certificate(
                    binary: [Byte(0), Byte(0), Byte(0), Byte(5), Byte(0), Byte(0), Byte(0), Byte(0), Byte(0)]
                )
            }
        }
    }
}

extension `RFC_8446.Extension.OidFilters Tests` {
    @Suite struct `Parse` {
        @Test func `parse rejects an empty OID`() {
            #expect(throws: RFC_8446.Extension.OidFilters.Error.invalidOIDLength(0)) {
                _ = try RFC_8446.Extension.OidFilters(
                    binary: [Byte(0), Byte(3), Byte(0), Byte(0), Byte(0)]
                )
            }
        }
    }
}

extension `RFC_8446.Extension.SupportedVersions.ClientHello Tests` {
    @Suite struct `Parse` {
        @Test func `parse rejects an empty version list`() {
            #expect(throws: RFC_8446.Extension.SupportedVersions.Error.invalidVersionCount(0)) {
                _ = try RFC_8446.Extension.SupportedVersions.ClientHello(binary: [Byte(0)])
            }
        }
    }
}
