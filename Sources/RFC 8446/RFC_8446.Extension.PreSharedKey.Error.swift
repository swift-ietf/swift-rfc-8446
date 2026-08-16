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

// RFC_8446.Extension.PreSharedKey.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.11: Pre-Shared Key Extension

extension RFC_8446.Extension.PreSharedKey {
    /// Errors raised when parsing any form of `pre_shared_key`.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before an identity, binder, or field was complete.
        case truncated

        /// Bytes remained after the payload.
        case trailingData(_ remaining: Int)

        /// A PskIdentity identity length is outside 1...65535.
        case invalidIdentityLength(_ count: Int)

        /// A PskBinderEntry length is outside 32...255.
        case invalidBinderLength(_ count: Int)

        /// The serialized OfferedPsks payload exceeds the extension_data bound.
        case offeredPsksTooLong(_ byteCount: Int)
    }
}

extension RFC_8446.Extension.PreSharedKey.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS pre_shared_key truncated"

        case .trailingData(let remaining):
            return "TLS pre_shared_key has \(remaining) trailing bytes"

        case .invalidIdentityLength(let count):
            return "TLS pre_shared_key identity length invalid: \(count) bytes (expected 1...65535)"

        case .invalidBinderLength(let count):
            return "TLS pre_shared_key binder length invalid: \(count) bytes (expected 32...255)"

        case .offeredPsksTooLong(let byteCount):
            return "TLS pre_shared_key OfferedPsks too long: \(byteCount) bytes (max 65535)"
        }
    }
}
