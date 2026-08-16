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

// RFC_8446.Extension.SupportedVersions.ClientHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.1: Supported Versions

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.SupportedVersions {
    /// ClientHello form of `supported_versions`: the offered version list.
    ///
    /// ```
    /// ProtocolVersion versions<2..254>;
    /// ```
    ///
    /// The list is `uint8`-length-prefixed (byte length, hence the 254 upper
    /// bound).
    public struct ClientHello: Sendable, Hashable {
        /// The offered versions, most preferred first.
        public let versions: [RFC_8446.ProtocolVersion]

        /// Creates a ClientHello supported_versions payload.
        ///
        /// - Throws: `Error.invalidVersionCount` if the version count is
        ///   outside 1...127 (the `uint8` byte-length bound of 254).
        public init(
            versions: [RFC_8446.ProtocolVersion]
        ) throws(RFC_8446.Extension.SupportedVersions.Error) {
            guard (1...127).contains(versions.count) else {
                throw .invalidVersionCount(versions.count)
            }
            self.versions = versions
        }

        /// Creates a ClientHello supported_versions payload WITHOUT validation (parse path).
        init(__unchecked: Void, versions: [RFC_8446.ProtocolVersion]) {
            self.versions = versions
        }

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                __unchecked: (),
                type: RFC_8446.Extension.SupportedVersions.extensionType,
                data: self.bytes
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.SupportedVersions.ClientHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for version in value.versions {
            block.append(contentsOf: version.rawValue.bytes(endianness: .big))
        }
        RFC_8446.Wire.appendVector8(block, into: &buffer)
    }

    /// Parses a ClientHello supported_versions `extension_data` body.
    public init<Bytes: Swift.Collection>(
        binary bytes: Bytes
    ) throws(RFC_8446.Extension.SupportedVersions.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector8()
            var sub = RFC_8446.Wire.Reader(block)
            var versions: [RFC_8446.ProtocolVersion] = []
            while !sub.isAtEnd {
                versions.append(RFC_8446.ProtocolVersion(rawValue: try sub.uint16()))
            }
            try reader.expectEnd()
            self.init(__unchecked: (), versions: versions)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
