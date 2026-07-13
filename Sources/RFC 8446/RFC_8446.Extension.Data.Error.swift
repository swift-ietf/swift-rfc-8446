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

// RFC_8446.Extension.Data.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2: Extensions

extension RFC_8446.Extension.Data {
    /// Errors raised when parsing a single extension envelope.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the type/length/data were complete.
        case truncated

        /// Bytes remained after the declared `extension_data` length.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.Data.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS extension truncated"
        case .trailingData(let remaining):
            return "TLS extension has \(remaining) trailing bytes"
        }
    }
}
