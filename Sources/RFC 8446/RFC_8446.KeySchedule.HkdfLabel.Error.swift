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

// RFC_8446.KeySchedule.HkdfLabel.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1: Key Schedule

extension RFC_8446.KeySchedule.HkdfLabel {
    /// Errors raised when parsing an `HkdfLabel`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before a field was complete.
        case truncated

        /// Bytes remained after the context.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.KeySchedule.HkdfLabel.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS HkdfLabel truncated"

        case .trailingData(let remaining):
            return "TLS HkdfLabel has \(remaining) trailing bytes"
        }
    }
}
