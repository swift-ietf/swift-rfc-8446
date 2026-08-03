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

// RFC_8446.Handshake.Certificate.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.2: Certificate

extension RFC_8446.Handshake.Certificate {
    /// Errors raised when parsing a Certificate payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field or entry was complete.
        case truncated

        /// Bytes remained after the certificate list.
        case trailingData(_ remaining: Int)

        /// The certificate_request_context exceeds 255 bytes.
        case invalidContextLength(_ count: Int)

        /// A cert_data blob is outside 1...2^24-1 bytes.
        case invalidCertificateDataLength(_ count: Int)

        /// A per-entry serialized extensions block exceeds 65535 bytes.
        case entryExtensionsTooLong(_ byteCount: Int)

        /// The serialized certificate_list exceeds the uint24 body bound.
        case certificateListTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Handshake.Certificate.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS Certificate truncated"

        case .trailingData(let remaining):
            return "TLS Certificate has \(remaining) trailing bytes"

        case .invalidContextLength(let count):
            return "TLS Certificate context length invalid: \(count) bytes (max 255)"

        case .invalidCertificateDataLength(let count):
            return "TLS Certificate cert_data length invalid: \(count) bytes (expected 1...16777215)"

        case .entryExtensionsTooLong(let byteCount):
            return "TLS CertificateEntry extensions too long: \(byteCount) bytes (max 65535)"

        case .certificateListTooLong(let byteCount):
            return "TLS Certificate certificate_list too long: \(byteCount) bytes"
        }
    }
}
