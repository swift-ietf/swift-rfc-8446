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

// RFC_8446.Extension.EarlyData.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.10: Early Data Indication

extension RFC_8446.Extension.EarlyData {
    /// Errors raised when parsing either form of `early_data`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the field was complete.
        case truncated

        /// Bytes remained after the payload (or the indication body was non-empty).
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.EarlyData.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS early_data truncated"
        case .trailingData(let remaining):
            return "TLS early_data has \(remaining) trailing bytes"
        }
    }
}
