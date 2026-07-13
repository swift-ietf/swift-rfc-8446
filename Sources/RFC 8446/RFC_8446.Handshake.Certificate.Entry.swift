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

// RFC_8446.Handshake.Certificate.Entry.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.4.2: Certificate

public import Binary_Serializable_Primitives

extension RFC_8446.Handshake.Certificate {
    /// A single entry in a Certificate message's `certificate_list`.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     select (certificate_type) {
    ///         case RawPublicKey:
    ///           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
    ///         case X509:
    ///           opaque cert_data<1..2^24-1>;
    ///     };
    ///     Extension extensions<0..2^16-1>;
    /// } CertificateEntry;
    /// ```
    ///
    /// The `certificate_type` is negotiated out of band (EncryptedExtensions),
    /// not carried in the entry; on the wire both arms are the same
    /// `uint24`-length opaque blob, stored here as ``certificateData``.
    public struct Entry: Sendable, Hashable {
        /// The `cert_data` / `ASN1_subjectPublicKeyInfo` opaque blob.
        public let certificateData: [Byte]

        /// Per-entry `extensions` (e.g. OCSP status, SCT).
        public let extensions: [RFC_8446.Extension.Data]

        /// Creates a certificate entry.
        public init(certificateData: [Byte], extensions: [RFC_8446.Extension.Data] = []) {
            self.certificateData = certificateData
            self.extensions = extensions
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Handshake.Certificate.Entry: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ entry: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendVector24(entry.certificateData, into: &buffer)
        RFC_8446.Wire.appendExtensions(entry.extensions, into: &buffer)
    }
}

// MARK: - Wire Decoding

extension RFC_8446.Wire.Reader {
    /// Reads one ``RFC_8446/Handshake/Certificate/Entry`` from the cursor.
    mutating func certificateEntry() throws(RFC_8446.Wire.Error)
    -> RFC_8446.Handshake.Certificate.Entry {
        let data = try vector24()
        let entryExtensions = try extensions()
        return RFC_8446.Handshake.Certificate.Entry(certificateData: data, extensions: entryExtensions)
    }
}
