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

// RFC_8446.Extension.OidFilters.Filter.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.5: OID Filters

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.OidFilters {
    /// A single OID/value filter.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     opaque certificate_extension_oid<1..2^8-1>;
    ///     opaque certificate_extension_values<0..2^16-1>;
    /// } OIDFilter;
    /// ```
    public struct Filter: Sendable, Hashable {
        /// DER-encoded `certificate_extension_oid` (opaque byte-domain).
        public let certificateExtensionOID: [Byte]

        /// DER-encoded `certificate_extension_values` (opaque byte-domain).
        public let certificateExtensionValues: [Byte]

        /// Creates an OID filter.
        public init(certificateExtensionOID: [Byte], certificateExtensionValues: [Byte]) {
            self.certificateExtensionOID = certificateExtensionOID
            self.certificateExtensionValues = certificateExtensionValues
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.OidFilters.Filter: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ filter: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector8(filter.certificateExtensionOID, into: &buffer)
        RFC_8446.Wire.appendVector16(filter.certificateExtensionValues, into: &buffer)
    }
}

// MARK: - Wire Decoding

extension RFC_8446.Wire.Reader {
    /// Reads one ``RFC_8446/Extension/OidFilters/Filter`` from the cursor.
    mutating func oidFilter() throws(RFC_8446.Wire.Error) -> RFC_8446.Extension.OidFilters.Filter {
        let oid = try vector8()
        let values = try vector16()
        return RFC_8446.Extension.OidFilters.Filter(
            certificateExtensionOID: oid,
            certificateExtensionValues: values
        )
    }
}
