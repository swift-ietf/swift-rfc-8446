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

// RFC_8446.Extension.PreSharedKey.OfferedPsks.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.11: Pre-Shared Key Extension

public import Binary_Serializable_Primitives

extension RFC_8446.Extension.PreSharedKey {
    /// ClientHello form of `pre_shared_key`: the offered identities and their
    /// binders.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// opaque PskBinderEntry<32..255>;
    ///
    /// struct {
    ///     PskIdentity identities<7..2^16-1>;
    ///     PskBinderEntry binders<33..2^16-1>;
    /// } OfferedPsks;
    /// ```
    ///
    /// Each binder is a `uint8`-length-prefixed opaque value (the 255 bound).
    /// The `binders` and `identities` lists are index-aligned.
    public struct OfferedPsks: Sendable, Hashable {
        /// The offered PSK identities.
        public let identities: [Identity]

        /// The binder values (one per identity, in the same order).
        public let binders: [[Byte]]

        /// Creates an OfferedPsks payload.
        public init(identities: [Identity], binders: [[Byte]]) {
            self.identities = identities
            self.binders = binders
        }

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(
                type: RFC_8446.Extension.PreSharedKey.extensionType,
                data: self.bytes
            )
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.PreSharedKey.OfferedPsks: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        var identitiesBlock: [Byte] = []
        for identity in value.identities {
            RFC_8446.Extension.PreSharedKey.Identity.serialize(identity, into: &identitiesBlock)
        }
        RFC_8446.Wire.appendVector16(identitiesBlock, into: &buffer)

        var bindersBlock: [Byte] = []
        for binder in value.binders {
            RFC_8446.Wire.appendVector8(binder, into: &bindersBlock)
        }
        RFC_8446.Wire.appendVector16(bindersBlock, into: &buffer)
    }

    /// Parses a ClientHello pre_shared_key `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(RFC_8446.Extension.PreSharedKey.Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let identitiesBlock = try reader.vector16()
            var identitiesReader = RFC_8446.Wire.Reader(identitiesBlock)
            var identities: [RFC_8446.Extension.PreSharedKey.Identity] = []
            while !identitiesReader.isAtEnd {
                identities.append(try identitiesReader.pskIdentity())
            }

            let bindersBlock = try reader.vector16()
            var bindersReader = RFC_8446.Wire.Reader(bindersBlock)
            var binders: [[Byte]] = []
            while !bindersReader.isAtEnd {
                binders.append(try bindersReader.vector8())
            }

            try reader.expectEnd()
            self.init(identities: identities, binders: binders)
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
