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

// RFC_8446.Extension.Padding.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2 (padding registered here); payload per RFC 7685

public import Binary_Serializable_Primitives

extension RFC_8446.Extension {
    /// `padding` extension payload (`extension_data` body), per RFC 7685.
    ///
    /// The `extension_data` is an opaque run of bytes (SHOULD be all zero);
    /// there is no internal length prefix — the run fills the extension.
    /// Receivers SHOULD NOT check the contents, so parsing has no failure mode.
    public struct Padding: Sendable, Hashable {
        /// The padding bytes (SHOULD be all zero).
        public let padding: [Byte]

        /// Creates a padding payload from explicit bytes.
        ///
        /// - Throws: `Error.invalidPaddingLength` if `padding` exceeds the
        ///   65535-byte `extension_data` ceiling.
        public init(padding: [Byte]) throws(Error) {
            guard padding.count <= 0xFFFF else {
                throw Error.invalidPaddingLength(padding.count)
            }
            self.padding = padding
        }

        /// Creates a padding payload of `length` zero bytes.
        ///
        /// - Throws: `Error.invalidPaddingLength` if `length` is outside
        ///   0...65535.
        public init(length: Int) throws(Error) {
            guard (0...0xFFFF).contains(length) else {
                throw Error.invalidPaddingLength(length)
            }
            self.padding = Array(repeating: Byte(0), count: length)
        }

        /// Creates a padding payload WITHOUT validation (parse path).
        init(__unchecked: Void, padding: [Byte]) {
            self.padding = padding
        }

        /// The extension type for this payload (`padding`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .padding

        /// Wraps this payload in a generic ``RFC_8446/Extension/Data`` envelope.
        public var extensionData: RFC_8446.Extension.Data {
            RFC_8446.Extension.Data(__unchecked: (), type: Self.extensionType, data: self.bytes)
        }
    }
}

// MARK: - Binary.Serializable

extension RFC_8446.Extension.Padding: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        buffer.append(contentsOf: value.padding)
    }

    /// Parses a padding `extension_data` body (the entire run of bytes).
    public init<Bytes: Collection>(binary bytes: Bytes) where Bytes.Element == Byte {
        self.init(__unchecked: (), padding: Array(bytes))
    }
}
