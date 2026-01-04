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

// RFC_8446.Alert.Description.swift
// swift-rfc-8446
//
// RFC 8446 Section 6: Alert Protocol

extension RFC_8446.Alert {
    /// Alert Description
    ///
    /// Describes the specific alert condition.
    public struct Description: RawRepresentable, Sendable, Hashable, Codable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Creates a Description WITHOUT validation
        init(__unchecked: Void, rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }
}

// MARK: - Closure Alerts

extension RFC_8446.Alert.Description {
    /// close_notify (0)
    public static let closeNotify = Self(__unchecked: (), rawValue: 0)
}

// MARK: - Error Alerts

extension RFC_8446.Alert.Description {
    /// unexpected_message (10)
    public static let unexpectedMessage = Self(__unchecked: (), rawValue: 10)

    /// bad_record_mac (20)
    public static let badRecordMac = Self(__unchecked: (), rawValue: 20)

    /// record_overflow (22)
    public static let recordOverflow = Self(__unchecked: (), rawValue: 22)

    /// handshake_failure (40)
    public static let handshakeFailure = Self(__unchecked: (), rawValue: 40)

    /// bad_certificate (42)
    public static let badCertificate = Self(__unchecked: (), rawValue: 42)

    /// unsupported_certificate (43)
    public static let unsupportedCertificate = Self(__unchecked: (), rawValue: 43)

    /// certificate_revoked (44)
    public static let certificateRevoked = Self(__unchecked: (), rawValue: 44)

    /// certificate_expired (45)
    public static let certificateExpired = Self(__unchecked: (), rawValue: 45)

    /// certificate_unknown (46)
    public static let certificateUnknown = Self(__unchecked: (), rawValue: 46)

    /// illegal_parameter (47)
    public static let illegalParameter = Self(__unchecked: (), rawValue: 47)

    /// unknown_ca (48)
    public static let unknownCA = Self(__unchecked: (), rawValue: 48)

    /// access_denied (49)
    public static let accessDenied = Self(__unchecked: (), rawValue: 49)

    /// decode_error (50)
    public static let decodeError = Self(__unchecked: (), rawValue: 50)

    /// decrypt_error (51)
    public static let decryptError = Self(__unchecked: (), rawValue: 51)

    /// protocol_version (70)
    public static let protocolVersion = Self(__unchecked: (), rawValue: 70)

    /// insufficient_security (71)
    public static let insufficientSecurity = Self(__unchecked: (), rawValue: 71)

    /// internal_error (80)
    public static let internalError = Self(__unchecked: (), rawValue: 80)

    /// inappropriate_fallback (86)
    public static let inappropriateFallback = Self(__unchecked: (), rawValue: 86)

    /// user_canceled (90)
    public static let userCanceled = Self(__unchecked: (), rawValue: 90)

    /// missing_extension (109)
    public static let missingExtension = Self(__unchecked: (), rawValue: 109)

    /// unsupported_extension (110)
    public static let unsupportedExtension = Self(__unchecked: (), rawValue: 110)

    /// unrecognized_name (112)
    public static let unrecognizedName = Self(__unchecked: (), rawValue: 112)

    /// bad_certificate_status_response (113)
    public static let badCertificateStatusResponse = Self(__unchecked: (), rawValue: 113)

    /// unknown_psk_identity (115)
    public static let unknownPSKIdentity = Self(__unchecked: (), rawValue: 115)

    /// certificate_required (116)
    public static let certificateRequired = Self(__unchecked: (), rawValue: 116)

    /// no_application_protocol (120)
    public static let noApplicationProtocol = Self(__unchecked: (), rawValue: 120)
}

// MARK: - CustomStringConvertible

extension RFC_8446.Alert.Description: CustomStringConvertible {
    public var description: String {
        switch rawValue {
        case 0: return "close_notify"
        case 10: return "unexpected_message"
        case 20: return "bad_record_mac"
        case 22: return "record_overflow"
        case 40: return "handshake_failure"
        case 42: return "bad_certificate"
        case 43: return "unsupported_certificate"
        case 44: return "certificate_revoked"
        case 45: return "certificate_expired"
        case 46: return "certificate_unknown"
        case 47: return "illegal_parameter"
        case 48: return "unknown_ca"
        case 49: return "access_denied"
        case 50: return "decode_error"
        case 51: return "decrypt_error"
        case 70: return "protocol_version"
        case 71: return "insufficient_security"
        case 80: return "internal_error"
        case 86: return "inappropriate_fallback"
        case 90: return "user_canceled"
        case 109: return "missing_extension"
        case 110: return "unsupported_extension"
        case 112: return "unrecognized_name"
        case 113: return "bad_certificate_status_response"
        case 115: return "unknown_psk_identity"
        case 116: return "certificate_required"
        case 120: return "no_application_protocol"
        default: return "alert(\(rawValue))"
        }
    }
}
