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

// RFC_8446.Handshake.CertificateVerify.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.3: Certificate Verify

extension RFC_8446.Handshake.CertificateVerify {
    /// Errors raised when parsing a CertificateVerify payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the signature.
        case trailingData(_ remaining: Int)

        /// The signature exceeds the uint16 length bound (65535 bytes).
        case signatureTooLong(_ count: Int)
    }
}

extension RFC_8446.Handshake.CertificateVerify.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS CertificateVerify truncated"
        case .trailingData(let remaining):
            return "TLS CertificateVerify has \(remaining) trailing bytes"
        case .signatureTooLong(let count):
            return "TLS CertificateVerify signature too long: \(count) bytes (max 65535)"
        }
    }
}
