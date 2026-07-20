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

// RFC_8446.Extension.OidFilters.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.5: OID Filters

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `oid_filters` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     OIDFilter filters<0..2^16-1>;
    /// } OIDFilterExtension;
    /// ```
    public struct OidFilters: Sendable, Hashable {
        /// The OID/value ``Filter`` list.
        public let filters: [Filter]

        /// Creates an oid_filters payload.
        ///
        /// - Throws: `Error.filtersTooLong` if the serialized filters block
        ///   exceeds 65533 bytes.
        public init(filters: [Filter]) throws(Error) {
            let blockLength = filters.reduce(0) {
                $0 + 1 + $1.certificateExtensionOID.count + 2 + $1.certificateExtensionValues.count
            }
            guard blockLength <= 0xFFFD else {
                throw Error.filtersTooLong(blockLength)
            }
            self.filters = filters
        }

        /// Creates an oid_filters payload WITHOUT validation (parse path).
        init(__unchecked: Void, filters: [Filter]) {
            self.filters = filters
        }

        /// The extension type for this payload (`oid_filters`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .oidFilters

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.OidFilters: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for filter in value.filters {
            Filter.serialize(filter, into: &block)
        }
        RFC_8446.Wire.appendVector16(block, into: &buffer)
    }

    /// Parses an oid_filters `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var filters: [Filter] = []
            while !sub.isAtEnd {
                filters.append(try sub.oidFilter())
            }
            try reader.expectEnd()
            self.init(__unchecked: (), filters: filters)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
