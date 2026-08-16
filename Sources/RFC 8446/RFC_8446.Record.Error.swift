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

// RFC_8446.Record.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 5.1: Record Layer

extension RFC_8446.Record {
    /// Errors that can occur when working with TLS records
    public enum Error: Swift.Error, Sendable, Equatable {
        /// Fragment exceeds maximum allowed size
        case fragmentTooLarge(_ size: Int)

        /// Record is truncated
        case truncated(_ size: Int)
    }
}

extension RFC_8446.Record.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .fragmentTooLarge(let size):
            return
                "TLS record fragment too large: \(size) bytes (max \(RFC_8446.Record.Limits.maxPlaintextLength))"

        case .truncated(let size):
            return "TLS record truncated: \(size) bytes"
        }
    }
}
