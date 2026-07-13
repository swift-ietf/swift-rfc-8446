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

// RFC_8446.Extension.Cookie.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.2: Cookie

extension RFC_8446.Extension.Cookie {
    /// Errors raised when parsing a cookie payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the cookie was complete.
        case truncated

        /// Bytes remained after the cookie.
        case trailingData(_ remaining: Int)
    }
}

extension RFC_8446.Extension.Cookie.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS cookie truncated"
        case .trailingData(let remaining):
            return "TLS cookie has \(remaining) trailing bytes"
        }
    }
}
