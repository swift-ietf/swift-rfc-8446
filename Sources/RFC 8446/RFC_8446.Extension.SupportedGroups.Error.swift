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

// RFC_8446.Extension.SupportedGroups.Error.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.7: Supported Groups

extension RFC_8446.Extension.SupportedGroups {
    /// Errors raised when parsing a supported_groups payload.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The input ended before the group list was complete.
        case truncated

        /// Bytes remained after the group list.
        case trailingData(_ remaining: Int)

        /// The named_group_list count is outside 1...32766.
        case invalidGroupCount(_ count: Int)
    }
}

extension RFC_8446.Extension.SupportedGroups.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .truncated:
            return "TLS supported_groups truncated"

        case .trailingData(let remaining):
            return "TLS supported_groups has \(remaining) trailing bytes"

        case .invalidGroupCount(let count):
            return "TLS supported_groups group count invalid: \(count) (expected 1...32766)"
        }
    }
}
