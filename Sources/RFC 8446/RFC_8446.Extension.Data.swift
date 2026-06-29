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

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// Generic TLS Extension
    ///
    /// Contains an extension type and opaque data.
    public struct Data: Sendable, Hashable {
        /// Extension type
        public let type: ExtensionType

        /// Extension data (opaque byte-domain payload)
        public let data: [Byte]

        /// Creates an extension
        public init(type: ExtensionType, data: [Byte]) {
            self.type = type
            self.data = data
        }

        // Stdlib-interop UInt8 forwarder lives in `RFC 8446 Standard Library
        // Integration` per [API-BYTE-007].
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.Data: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ ext: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // Extension type (UInt16 stays UInt16 — assumed; serialize via
        // Byte-primary BinaryInteger.bytes(endianness:)).
        buffer.append(contentsOf: ext.type.rawValue.bytes(endianness: .big))

        // Extension data length (2 bytes UInt16)
        let length = UInt16(ext.data.count)
        buffer.append(contentsOf: length.bytes(endianness: .big))

        // Extension data (opaque byte-domain payload, already [Byte])
        buffer.append(contentsOf: ext.data)
    }
}
