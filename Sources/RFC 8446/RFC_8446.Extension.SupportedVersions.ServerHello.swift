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

// RFC_8446.Extension.SupportedVersions.ServerHello.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.1: Supported Versions

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.SupportedVersions {
    /// ServerHello (and HelloRetryRequest) form of `supported_versions`: the
    /// single selected version.
    ///
    /// ```
    /// ProtocolVersion selected_version;
    /// ```
    public struct ServerHello: Sendable, Hashable {
        /// The single selected version (0x0304 for TLS 1.3).
        public let selectedVersion: RFC_8446.ProtocolVersion

        /// Creates a ServerHello supported_versions payload.
        public init(selectedVersion: RFC_8446.ProtocolVersion) {
            self.selectedVersion = selectedVersion
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

extension RFC_8446.Extension.SupportedVersions.ServerHello: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.selectedVersion.rawValue.bytes(endianness: .big))
    }

    /// Parses a ServerHello supported_versions `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.SupportedVersions.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let version = try reader.uint16()
            try reader.expectEnd()
            self.init(selectedVersion: RFC_8446.ProtocolVersion(rawValue: version))
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
