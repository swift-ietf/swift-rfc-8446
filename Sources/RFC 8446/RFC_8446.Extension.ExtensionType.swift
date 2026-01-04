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

// RFC_8446.Extension.ExtensionType.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2: Extensions

extension RFC_8446.Extension {
    /// Extension Type
    ///
    /// Identifies the type of TLS extension.
    public struct ExtensionType: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// Creates an ExtensionType WITHOUT validation
        init(__unchecked: Void, rawValue: UInt16) {
            self.rawValue = rawValue
        }
    }
}

// MARK: - Standard Extensions

extension RFC_8446.Extension.ExtensionType {
    /// server_name (0) - RFC 6066
    public static let serverName = Self(__unchecked: (), rawValue: 0)

    /// max_fragment_length (1) - RFC 6066
    public static let maxFragmentLength = Self(__unchecked: (), rawValue: 1)

    /// status_request (5) - RFC 6066
    public static let statusRequest = Self(__unchecked: (), rawValue: 5)

    /// supported_groups (10) - RFC 8446
    public static let supportedGroups = Self(__unchecked: (), rawValue: 10)

    /// signature_algorithms (13) - RFC 8446
    public static let signatureAlgorithms = Self(__unchecked: (), rawValue: 13)

    /// use_srtp (14) - RFC 5764
    public static let useSRTP = Self(__unchecked: (), rawValue: 14)

    /// heartbeat (15) - RFC 6520
    public static let heartbeat = Self(__unchecked: (), rawValue: 15)

    /// application_layer_protocol_negotiation (16) - RFC 7301
    public static let alpn = Self(__unchecked: (), rawValue: 16)

    /// signed_certificate_timestamp (18) - RFC 6962
    public static let signedCertificateTimestamp = Self(__unchecked: (), rawValue: 18)

    /// client_certificate_type (19) - RFC 7250
    public static let clientCertificateType = Self(__unchecked: (), rawValue: 19)

    /// server_certificate_type (20) - RFC 7250
    public static let serverCertificateType = Self(__unchecked: (), rawValue: 20)

    /// padding (21) - RFC 7685
    public static let padding = Self(__unchecked: (), rawValue: 21)

    /// pre_shared_key (41) - RFC 8446
    public static let preSharedKey = Self(__unchecked: (), rawValue: 41)

    /// early_data (42) - RFC 8446
    public static let earlyData = Self(__unchecked: (), rawValue: 42)

    /// supported_versions (43) - RFC 8446
    public static let supportedVersions = Self(__unchecked: (), rawValue: 43)

    /// cookie (44) - RFC 8446
    public static let cookie = Self(__unchecked: (), rawValue: 44)

    /// psk_key_exchange_modes (45) - RFC 8446
    public static let pskKeyExchangeModes = Self(__unchecked: (), rawValue: 45)

    /// certificate_authorities (47) - RFC 8446
    public static let certificateAuthorities = Self(__unchecked: (), rawValue: 47)

    /// oid_filters (48) - RFC 8446
    public static let oidFilters = Self(__unchecked: (), rawValue: 48)

    /// post_handshake_auth (49) - RFC 8446
    public static let postHandshakeAuth = Self(__unchecked: (), rawValue: 49)

    /// signature_algorithms_cert (50) - RFC 8446
    public static let signatureAlgorithmsCert = Self(__unchecked: (), rawValue: 50)

    /// key_share (51) - RFC 8446
    public static let keyShare = Self(__unchecked: (), rawValue: 51)
}

// MARK: - CustomStringConvertible

extension RFC_8446.Extension.ExtensionType: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "server_name"
        case 1: return "max_fragment_length"
        case 5: return "status_request"
        case 10: return "supported_groups"
        case 13: return "signature_algorithms"
        case 14: return "use_srtp"
        case 15: return "heartbeat"
        case 16: return "application_layer_protocol_negotiation"
        case 18: return "signed_certificate_timestamp"
        case 19: return "client_certificate_type"
        case 20: return "server_certificate_type"
        case 21: return "padding"
        case 41: return "pre_shared_key"
        case 42: return "early_data"
        case 43: return "supported_versions"
        case 44: return "cookie"
        case 45: return "psk_key_exchange_modes"
        case 47: return "certificate_authorities"
        case 48: return "oid_filters"
        case 49: return "post_handshake_auth"
        case 50: return "signature_algorithms_cert"
        case 51: return "key_share"
        default: return "extension(\(rawValue))"
        }
    }
}
