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

// RFC_8446.Handshake.CertificateRequest.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.3.2: Certificate Request

extension RFC_8446.Handshake.CertificateRequest {
    /// Errors raised when parsing a CertificateRequest payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the extensions block.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.CertificateRequest.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS CertificateRequest truncated"
        case .trailingData(let remaining):
            return "TLS CertificateRequest has \(remaining) trailing bytes"
        }
    }
}
