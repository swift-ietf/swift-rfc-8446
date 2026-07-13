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

// RFC_8446.Extension.SignatureAlgorithms.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.3: Signature Algorithms

extension RFC_8446.Extension.SignatureAlgorithms {
    /// Errors raised when parsing a signature_algorithms payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the scheme list was complete.
        case truncated

        /// Bytes remained after the scheme list.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.SignatureAlgorithms.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS signature_algorithms truncated"
        case .trailingData(let remaining):
            return "TLS signature_algorithms has \(remaining) trailing bytes"
        }
    }
}
