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

// RFC_8446.Extension.SupportedGroups.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.7: Supported Groups

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `supported_groups` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     NamedGroup named_group_list<2..2^16-1>;
    /// } NamedGroupList;
    /// ```
    public struct SupportedGroups: Sendable, Hashable {
        /// The named groups, most preferred first.
        public let namedGroupList: [NamedGroup]

        /// Creates a supported_groups payload.
        ///
        /// - Throws: `Error.invalidGroupCount` if the group count is outside
        ///   1...32766 (the `uint16` byte-length bound within the
        ///   `extension_data` ceiling).
        public init(namedGroupList: [NamedGroup]) throws(Error) {
            guard (1...32766).contains(namedGroupList.count) else {
                throw Error.invalidGroupCount(namedGroupList.count)
            }
            self.namedGroupList = namedGroupList
        }

        /// Creates a supported_groups payload WITHOUT validation (parse path).
        init(__unchecked: Void, namedGroupList: [NamedGroup]) {
            self.namedGroupList = namedGroupList
        }

        /// The extension type for this payload (`supported_groups`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .supportedGroups

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.SupportedGroups: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendUInt16List(value.namedGroupList.map(\.rawValue), into: &buffer)
    }

    /// Parses a supported_groups `extension_data` body.
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let values = try reader.uint16List()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                namedGroupList: values.map(RFC_8446.Extension.NamedGroup.init(rawValue:))
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
