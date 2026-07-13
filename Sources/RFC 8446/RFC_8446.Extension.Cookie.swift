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

// RFC_8446.Extension.Cookie.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.2: Cookie

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `cookie` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque cookie<1..2^16-1>;
    /// } Cookie;
    /// ```
    public struct Cookie: Sendable, Hashable {
        /// The opaque cookie bytes.
        public let cookie: [Byte]

        /// Creates a cookie payload.
        public init(cookie: [Byte]) {
            self.cookie = cookie
        }

        /// The extension type for this payload (`cookie`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .cookie

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.Cookie: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector16(value.cookie, into: &buffer)
    }

    /// Parses a cookie `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let cookie = try reader.vector16()
            try reader.expectEnd()
            self.init(cookie: cookie)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
