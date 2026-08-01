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

// RFC_8446.Extension.PreSharedKey.ServerHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.11: Pre-Shared Key Extension

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.PreSharedKey {
    /// ServerHello form of `pre_shared_key`: the selected identity index.
    ///
    /// ```
    /// uint16 selected_identity;
    /// ```
    public struct ServerHello: Sendable, Hashable {
        /// The 0-based index into the client's identity list.
        public let selectedIdentity: UInt16

        /// Creates a ServerHello pre_shared_key payload.
        public init(selectedIdentity: UInt16) {
            self.selectedIdentity = selectedIdentity
        }

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.PreSharedKey.extensionType,
                data: self.bytes
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.PreSharedKey.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.selectedIdentity.bytes(endianness: .big))
    }

    /// Parses a ServerHello pre_shared_key `extension_data` body.
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.PreSharedKey.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let index = try reader.uint16()
            try reader.expectEnd()
            self.init(selectedIdentity: index)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
