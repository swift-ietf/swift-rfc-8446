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

// RFC_8446.Extension.SignatureScheme.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.3: Signature Algorithms

extension RFC_8446.Extension {
    /// Signature Scheme
    ///
    /// Identifies the signature algorithm.
    public struct SignatureScheme: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Creates a SignatureScheme WITHOUT validation
        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }
    }
}

// MARK: - RSASSA-PKCS1-v1_5

extension RFC_8446.Extension.SignatureScheme {
    /// rsa_pkcs1_sha256 (0x0401)
    public static let rsaPkcs1Sha256 = Self(__unchecked: (), rawValue: 0x0401)

    /// rsa_pkcs1_sha384 (0x0501)
    public static let rsaPkcs1Sha384 = Self(__unchecked: (), rawValue: 0x0501)

    /// rsa_pkcs1_sha512 (0x0601)
    public static let rsaPkcs1Sha512 = Self(__unchecked: (), rawValue: 0x0601)
}

// MARK: - ECDSA

extension RFC_8446.Extension.SignatureScheme {
    /// ecdsa_secp256r1_sha256 (0x0403)
    public static let ecdsaSecp256r1Sha256 = Self(__unchecked: (), rawValue: 0x0403)

    /// ecdsa_secp384r1_sha384 (0x0503)
    public static let ecdsaSecp384r1Sha384 = Self(__unchecked: (), rawValue: 0x0503)

    /// ecdsa_secp521r1_sha512 (0x0603)
    public static let ecdsaSecp521r1Sha512 = Self(__unchecked: (), rawValue: 0x0603)
}

// MARK: - RSASSA-PSS

extension RFC_8446.Extension.SignatureScheme {
    /// rsa_pss_rsae_sha256 (0x0804)
    public static let rsaPssRsaeSha256 = Self(__unchecked: (), rawValue: 0x0804)

    /// rsa_pss_rsae_sha384 (0x0805)
    public static let rsaPssRsaeSha384 = Self(__unchecked: (), rawValue: 0x0805)

    /// rsa_pss_rsae_sha512 (0x0806)
    public static let rsaPssRsaeSha512 = Self(__unchecked: (), rawValue: 0x0806)
}

// MARK: - EdDSA

extension RFC_8446.Extension.SignatureScheme {
    /// ed25519 (0x0807)
    public static let ed25519 = Self(__unchecked: (), rawValue: 0x0807)

    /// ed448 (0x0808)
    public static let ed448 = Self(__unchecked: (), rawValue: 0x0808)
}

// MARK: - RSASSA-PSS with OID

extension RFC_8446.Extension.SignatureScheme {
    /// rsa_pss_pss_sha256 (0x0809)
    public static let rsaPssPssSha256 = Self(__unchecked: (), rawValue: 0x0809)

    /// rsa_pss_pss_sha384 (0x080A)
    public static let rsaPssPssSha384 = Self(__unchecked: (), rawValue: 0x080A)

    /// rsa_pss_pss_sha512 (0x080B)
    public static let rsaPssPssSha512 = Self(__unchecked: (), rawValue: 0x080B)
}
