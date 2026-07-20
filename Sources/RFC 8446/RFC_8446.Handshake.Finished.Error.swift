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

// RFC_8446.Handshake.Finished.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.4: Finished

extension RFC_8446.Handshake.Finished {
    /// Errors raised when constructing a Finished payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// `verify_data` exceeds the handshake body `uint24` bound.
        case verifyDataTooLong(_ count: Int)
    }
}

extension RFC_8446.Handshake.Finished.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .verifyDataTooLong(let count):
            return "TLS Finished verify_data too long: \(count) bytes (max 16777215)"
        }
    }
}
