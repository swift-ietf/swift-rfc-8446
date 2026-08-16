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

// RFC_8446.Extension.KeyShare.ClientHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.8: Key Share

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.KeyShare {
    /// ClientHello form of `key_share`: the offered shares.
    ///
    /// ```
    /// struct {
    ///     KeyShareEntry client_shares<0..2^16-1>;
    /// } KeyShareClientHello;
    /// ```
    ///
    /// The list MAY be empty to request a HelloRetryRequest.
    public struct ClientHello: Sendable, Hashable {
        /// Offered key shares in descending order of preference.
        public let clientShares: [Entry]

        /// Creates a ClientHello key_share payload.
        ///
        /// - Throws: `Error.clientSharesTooLong` if the serialized
        ///   `client_shares` block exceeds 65533 bytes (the `uint16` block
        ///   bound within the `extension_data` ceiling).
        public init(clientShares: [Entry]) throws(RFC_8446.Extension.KeyShare.Error) {
            let blockLength = clientShares.reduce(0) { $0 + 4 + $1.keyExchange.count }
            guard blockLength <= 0xFFFD else {
                throw .clientSharesTooLong(blockLength)
            }
            self.clientShares = clientShares
        }

        /// Creates a ClientHello key_share payload WITHOUT validation (parse path).
        init(__unchecked: Void, clientShares: [Entry]) {
            self.clientShares = clientShares
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

extension RFC_8446.Extension.KeyShare.ClientHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for entry in value.clientShares {
            RFC_8446.Extension.KeyShare.Entry.serialize(entry, into: &block)
        }
        RFC_8446.Wire.appendVector16(block, into: &buffer)
    }

    /// Parses a ClientHello key_share `extension_data` body.
    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.KeyShare.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var entries: [RFC_8446.Extension.KeyShare.Entry] = []
            while !sub.isAtEnd {
                entries.append(try sub.keyShareEntry())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), clientShares: entries)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
