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

// RFC_8446.Handshake.EndOfEarlyData.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.5: End of Early Data

extension RFC_8446.Handshake.EndOfEarlyData {
    /// Errors raised when parsing an EndOfEarlyData payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The body was non-empty (EndOfEarlyData has an empty body).
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Handshake.EndOfEarlyData.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .trailingData(let remaining):
            return "TLS EndOfEarlyData has \(remaining) trailing bytes (body must be empty)"
        }
    }
}
