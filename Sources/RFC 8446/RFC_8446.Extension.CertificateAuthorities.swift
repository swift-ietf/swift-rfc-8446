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

// RFC_8446.Extension.CertificateAuthorities.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.4: Certificate Authorities

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `certificate_authorities` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// opaque DistinguishedName<1..2^16-1>;
    ///
    /// struct {
    ///     DistinguishedName authorities<3..2^16-1>;
    /// } CertificateAuthoritiesExtension;
    /// ```
    public struct CertificateAuthorities: Sendable, Hashable {
        /// The DER-encoded distinguished names of acceptable CAs (each opaque
        /// byte-domain).
        public let authorities: [[Byte]]

        /// Creates a certificate_authorities payload.
        public init(authorities: [[Byte]]) {
            self.authorities = authorities
        }

        /// The extension type for this payload (`certificate_authorities`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .certificateAuthorities

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.CertificateAuthorities: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var block: [Byte] = []
        for authority in value.authorities {
            RFC_8446.Wire.appendVector16(authority, into: &block)
        }
        RFC_8446.Wire.appendVector16(block, into: &buffer)
    }

    /// Parses a certificate_authorities `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let block = try reader.vector16()
            var sub = RFC_8446.Wire.Reader(block)
            var authorities: [[Byte]] = []
            while !sub.isAtEnd {
                authorities.append(try sub.vector16())
            }
            try reader.expectEnd()
            self.init(authorities: authorities)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
