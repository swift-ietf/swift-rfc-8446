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

// RFC_8446.Extension.SupportedVersions.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.1: Supported Versions

extension RFC_8446.Extension.SupportedVersions {
    /// Errors raised when parsing either form of `supported_versions`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the payload.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.SupportedVersions.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS supported_versions truncated"
        case .trailingData(let remaining):
            return "TLS supported_versions has \(remaining) trailing bytes"
        }
    }
}
