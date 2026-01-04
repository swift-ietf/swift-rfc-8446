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

// RFC_8446.Extension.Data.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2: Extensions

extension RFC_8446.Extension {
    /// Generic TLS Extension
    ///
    /// Contains an extension type and opaque data.
    public struct Data: Sendable, Hashable {
        /// Extension type
        public let type: ExtensionType

        /// Extension data
        public let data: [UInt8]

        /// Creates an extension
        public init(type: ExtensionType, data: [UInt8]) {
            self.type = type
            self.data = data
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.Data: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ ext: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == UInt8 {
        // Extension type (2 bytes)
        buffer.append(UInt8(ext.type.rawValue >> 8))
        buffer.append(UInt8(ext.type.rawValue & 0xFF))

        // Extension data length (2 bytes)
        buffer.append(UInt8(ext.data.count >> 8))
        buffer.append(UInt8(ext.data.count & 0xFF))

        // Extension data
        buffer.append(contentsOf: ext.data)
    }
}
