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

// RFC_8446.Extension.EarlyData.Ticket.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.10: Early Data Indication

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.EarlyData {
    /// NewSessionTicket form of `early_data`: the maximum 0-RTT data size.
    ///
    /// ```
    /// uint32 max_early_data_size;
    /// ```
    public struct Ticket: Sendable, Hashable {
        /// Maximum amount of 0-RTT data (bytes) the client may send.
        public let maxEarlyDataSize: UInt32

        /// Creates an early_data ticket payload.
        public init(maxEarlyDataSize: UInt32) {
            self.maxEarlyDataSize = maxEarlyDataSize
        }

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.EarlyData.extensionType,
                data: self.bytes
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.EarlyData.Ticket: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.maxEarlyDataSize.bytes(endianness: .big))
    }

    /// Parses an early_data ticket `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.EarlyData.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let size = try reader.uint32()
            try reader.expectEnd()
            self.init(maxEarlyDataSize: size)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
