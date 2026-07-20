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

// RFC_8446.Extension.CertificateAuthorities.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.4: Certificate Authorities

extension RFC_8446.Extension.CertificateAuthorities {
    /// Errors raised when parsing a certificate_authorities payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the authorities list was complete.
        case truncated

        /// Bytes remained after the authorities list.
        case trailingData(_ remaining: Int)

        /// A DistinguishedName length is outside 1...65535.
        case invalidAuthorityLength(_ count: Int)

        /// The serialized authorities block exceeds its uint16 bound.
        case authoritiesTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.CertificateAuthorities.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS certificate_authorities truncated"
        case .trailingData(let remaining):
            return "TLS certificate_authorities has \(remaining) trailing bytes"
        case .invalidAuthorityLength(let count):
            return "TLS certificate_authorities authority length invalid: \(count) bytes (expected 1...65535)"
        case .authoritiesTooLong(let byteCount):
            return "TLS certificate_authorities too long: \(byteCount) bytes (max 65533)"
        }
    }
}
