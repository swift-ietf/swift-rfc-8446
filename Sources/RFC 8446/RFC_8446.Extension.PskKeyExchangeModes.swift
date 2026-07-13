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

// RFC_8446.Extension.PskKeyExchangeModes.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.9: Pre-Shared Key Exchange Modes

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `psk_key_exchange_modes` extension payload (`extension_data` body).
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     PskKeyExchangeMode ke_modes<1..255>;
    /// } PskKeyExchangeModes;
    /// ```
    public struct PskKeyExchangeModes: Sendable, Hashable {
        /// The offered key exchange modes.
        public let keModes: [PskKeyExchangeMode]

        /// Creates a psk_key_exchange_modes payload.
        public init(keModes: [PskKeyExchangeMode]) {
            self.keModes = keModes
        }

        /// The extension type for this payload (`psk_key_exchange_modes`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .pskKeyExchangeModes

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.PskKeyExchangeModes: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // ke_modes<1..255> — a uint8-length-prefixed run of single-byte modes.
        let modeBytes = value.keModes.map { Byte($0.rawValue) }
        RFC_8446.Wire.appendVector8(modeBytes, into: &buffer)
    }

    /// Parses a psk_key_exchange_modes `extension_data` body.
    public init<Bytes: Collection>(binary bytes: Bytes) throws(Error)
    where Bytes.Element == Byte {
        var reader = RFC_8446.Wire.Reader(Array(bytes))
        do {
            let modeBytes = try reader.vector8()
            try reader.expectEnd()
            self.init(
                keModes: modeBytes.map { RFC_8446.Extension.PskKeyExchangeMode(rawValue: $0.underlying) }
            )
        } catch {
            switch error {
            case .trailingData(let n): throw .trailingData(n)
            case .truncated, .lengthOverflow: throw .truncated
            }
        }
    }
}
