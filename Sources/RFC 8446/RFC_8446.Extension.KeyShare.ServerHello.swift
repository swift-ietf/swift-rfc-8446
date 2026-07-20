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

// RFC_8446.Extension.KeyShare.ServerHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.8: Key Share

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.KeyShare {
    /// ServerHello form of `key_share`: the single selected share.
    ///
    /// ```
    /// struct {
    ///     KeyShareEntry server_share;
    /// } KeyShareServerHello;
    /// ```
    public struct ServerHello: Sendable, Hashable {
        /// The server's single selected key share.
        public let serverShare: Entry

        /// Creates a ServerHello key_share payload.
        public init(serverShare: Entry) {
            self.serverShare = serverShare
        }

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.KeyShare.extensionType,
                data: self.bytes
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.KeyShare.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Extension.KeyShare.Entry.serialize(value.serverShare, into: &buffer)
    }

    /// Parses a ServerHello key_share `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.KeyShare.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let entry = try reader.keyShareEntry()
            try reader.expectEnd()
            self.init(serverShare: entry)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
