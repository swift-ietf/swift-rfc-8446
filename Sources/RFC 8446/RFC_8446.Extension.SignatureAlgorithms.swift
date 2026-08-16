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

// RFC_8446.Extension.SignatureAlgorithms.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.3: Signature Algorithms

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `signature_algorithms` extension payload (`extension_data` body).
    ///
    /// Applies to signatures in CertificateVerify messages.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     SignatureScheme supported_signature_algorithms<2..2^16-2>;
    /// } SignatureSchemeList;
    /// ```
    public struct SignatureAlgorithms: Sendable, Hashable {
        /// The signature schemes, most preferred first.
        public let supportedSignatureAlgorithms: [SignatureScheme]

        /// Creates a signature_algorithms payload.
        ///
        /// - Throws: `Error.invalidAlgorithmCount` if the algorithm count is
        ///   outside 1...32766 (the `uint16` byte-length bound within the
        ///   `extension_data` ceiling).
        public init(supportedSignatureAlgorithms: [SignatureScheme]) throws(Error) {
            guard (1...32766).contains(supportedSignatureAlgorithms.count) else {
                throw Error.invalidAlgorithmCount(supportedSignatureAlgorithms.count)
            }
            self.supportedSignatureAlgorithms = supportedSignatureAlgorithms
        }

        /// Creates a signature_algorithms payload WITHOUT validation (parse path).
        init(__unchecked: Void, supportedSignatureAlgorithms: [SignatureScheme]) {
            self.supportedSignatureAlgorithms = supportedSignatureAlgorithms
        }

        /// The extension type for this payload (`signature_algorithms`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .signatureAlgorithms

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.SignatureAlgorithms: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        RFC_8446.Wire.appendUInt16List(
            value.supportedSignatureAlgorithms.map(\.rawValue),
            into: &buffer
        )
    }

    /// Parses a signature_algorithms `extension_data` body.
    public init<Bytes: Swift.Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let values = try reader.uint16List()
            try reader.expectEnd()
            self.init(
                __unchecked: (),
                supportedSignatureAlgorithms: values.map(
                    RFC_8446.Extension.SignatureScheme.init(rawValue:)
                )
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
