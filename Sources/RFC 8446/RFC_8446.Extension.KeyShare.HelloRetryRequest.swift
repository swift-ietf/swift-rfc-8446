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

// RFC_8446.Extension.KeyShare.HelloRetryRequest.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.8: Key Share

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.KeyShare {
    /// HelloRetryRequest form of `key_share`: the requested group.
    ///
    /// ```
    /// struct {
    ///     NamedGroup selected_group;
    /// } KeyShareHelloRetryRequest;
    /// ```
    public struct HelloRetryRequest: Sendable, Hashable {
        /// The group the server is requesting a retried key share for.
        public let selectedGroup: RFC_8446.Extension.NamedGroup

        /// Creates a HelloRetryRequest key_share payload.
        public init(selectedGroup: RFC_8446.Extension.NamedGroup) {
            self.selectedGroup = selectedGroup
        }

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                type: RFC_8446.Extension.KeyShare.extensionType,
                data: self.bytes
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.KeyShare.HelloRetryRequest: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.selectedGroup.rawValue.bytes(endianness: .big))
    }

    /// Parses a HelloRetryRequest key_share `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.KeyShare.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let group = try reader.uint16()
            try reader.expectEnd()
            self.init(selectedGroup: RFC_8446.Extension.NamedGroup(rawValue: group))
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
