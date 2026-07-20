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

// RFC_8446.Extension.Padding.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2 (padding registered here); payload per RFC 7685

extension RFC_8446.Extension.Padding {
    /// Errors raised when constructing a padding payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The padding length is outside 0...65535 (the `extension_data`
        /// `uint16` length bound).
        case invalidPaddingLength(_ count: Int)
    }
}

extension RFC_8446.Extension.Padding.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidPaddingLength(let count):
            return "TLS padding length invalid: \(count) bytes (expected 0...65535)"
        }
    }
}
