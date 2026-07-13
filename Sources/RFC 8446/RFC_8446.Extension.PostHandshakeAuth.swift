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

// RFC_8446.Extension.PostHandshakeAuth.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.6: Post-Handshake Client Authentication

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `post_handshake_auth` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {} PostHandshakeAuth;
    /// ```
    ///
    /// The `extension_data` field is zero length.
    public struct PostHandshakeAuth: Sendable, Hashable {
        /// Creates a post_handshake_auth payload.
        public init() {}

        /// The extension type for this payload (`post_handshake_auth`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .postHandshakeAuth

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: [])
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.PostHandshakeAuth: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // post_handshake_auth has an empty body — nothing to append.
    }

    /// Parses a post_handshake_auth `extension_data` body (which MUST be empty).
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else { throw .trailingData(bytes.count) }
        self.init()
    }
}
