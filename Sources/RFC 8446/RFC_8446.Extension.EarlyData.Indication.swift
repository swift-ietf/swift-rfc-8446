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

// RFC_8446.Extension.EarlyData.Indication.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.10: Early Data Indication

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.EarlyData {
    /// ClientHello / EncryptedExtensions form of `early_data`: an empty body.
    ///
    /// ```
    /// struct {} Empty;
    /// ```
    public struct Indication: Sendable, Hashable {
        /// Creates an early_data indication payload.
        public init() {}

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.EarlyData.extensionType,
                data: []
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.EarlyData.Indication: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // Empty body — nothing to append.
    }

    /// Parses an early_data indication `extension_data` body (which MUST be empty).
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.EarlyData.Error)
    where Bytes.Element == Byte {
        guard bytes.isEmpty else { throw .trailingData(bytes.count) }
        self.init()
    }
}
