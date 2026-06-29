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

// RFC_8446.CipherSuite.swift
// swift-rfc-8446
//
// RFC 8446 Appendix B.4: Cipher Suites

import Radix_Format_Primitives

extension RFC_8446 {
    /// TLS 1.3 Cipher Suite
    ///
    /// In TLS 1.3, cipher suites only define the symmetric cipher and hash
    /// algorithm. Key exchange and authentication are negotiated separately
    /// via extensions.
    ///
    /// ## TLS 1.3 Cipher Suites
    ///
    /// TLS 1.3 defines a new set of cipher suites that only specify:
    /// - AEAD algorithm
    /// - Hash algorithm for HKDF
    ///
    /// Key exchange is negotiated via the supported_groups and key_share extensions.
    /// Signature algorithms are negotiated via signature_algorithms extension.
    ///
    /// ## Format
    ///
    /// Cipher suites are 2-byte values assigned by IANA.
    public struct CipherSuite: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Creates a CipherSuite WITHOUT validation
        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }

        // MARK: - TLS 1.3 Cipher Suites

        /// TLS_AES_128_GCM_SHA256 (0x1301)
        ///
        /// Mandatory to implement for TLS 1.3.
        public static let aes128GcmSha256 = Self(__unchecked: (), rawValue: 0x1301)

        /// TLS_AES_256_GCM_SHA384 (0x1302)
        public static let aes256GcmSha384 = Self(__unchecked: (), rawValue: 0x1302)

        /// TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        public static let chacha20Poly1305Sha256 = Self(__unchecked: (), rawValue: 0x1303)

        /// TLS_AES_128_CCM_SHA256 (0x1304)
        public static let aes128CcmSha256 = Self(__unchecked: (), rawValue: 0x1304)

        /// TLS_AES_128_CCM_8_SHA256 (0x1305)
        public static let aes128Ccm8Sha256 = Self(__unchecked: (), rawValue: 0x1305)

        // MARK: - Classification

        /// Whether this is a TLS 1.3 cipher suite
        public var isTLS13: Bool {
            rawValue >= 0x1301 && rawValue <= 0x1305
        }

        /// AEAD algorithm name
        public var aeadAlgorithm: String? {
            switch rawValue {
            case 0x1301: return "AES-128-GCM"
            case 0x1302: return "AES-256-GCM"
            case 0x1303: return "ChaCha20-Poly1305"
            case 0x1304: return "AES-128-CCM"
            case 0x1305: return "AES-128-CCM-8"
            default: return nil
            }
        }

        /// Hash algorithm name
        public var hashAlgorithm: String? {
            switch rawValue {
            case 0x1301, 0x1303, 0x1304, 0x1305:
                return "SHA-256"
            case 0x1302:
                return "SHA-384"
            default:
                return nil
            }
        }

        /// Key length in bytes
        public var keyLength: Int? {
            switch rawValue {
            case 0x1301, 0x1304, 0x1305: return 16 // 128-bit
            case 0x1302, 0x1303: return 32 // 256-bit
            default: return nil
            }
        }
    }
}

extension RFC_8446.CipherSuite: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0x1301: return "TLS_AES_128_GCM_SHA256"
        case 0x1302: return "TLS_AES_256_GCM_SHA384"
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256"
        case 0x1304: return "TLS_AES_128_CCM_SHA256"
        case 0x1305: return "TLS_AES_128_CCM_8_SHA256"
        default:
            return "CipherSuite(\(rawValue.formatted(Radix.Format.hex.zeroPadded(width: 4).prefix)))"
        }
    }
}
