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

// RFC_8446.KeySchedule.Witness.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1: Key Schedule

public import Binary_Serializable_Primitives

extension RFC_8446.KeySchedule {
    /// The cryptographic witness for the key schedule.
    ///
    /// The core target is crypto-free: every hash and HKDF operation is
    /// supplied by the caller through these closures. A consumer adapts a real
    /// implementation (e.g. SHA-256 + HKDF over swift-crypto) *into* this
    /// witness; the schedule functions (``RFC_8446/KeySchedule``) then compose
    /// the witness to derive secrets. No behaviour, and no `Sendable`
    /// requirement, is imposed on the witness itself.
    ///
    /// The shapes mirror RFC 5869: `HKDF-Extract(salt, IKM) -> PRK` and
    /// `HKDF-Expand(PRK, info, L) -> OKM`, plus the cipher-suite `Hash`.
    public struct Witness {
        /// `Hash.length` in bytes (e.g. 32 for SHA-256, 48 for SHA-384).
        public let hashLength: Int

        /// The cipher-suite hash: `Hash(messages) -> digest`.
        public let hash: ([Byte]) -> [Byte]

        /// `HKDF-Extract(salt, IKM) -> PRK` (an HMAC over `IKM` keyed by `salt`).
        public let extract: (_ salt: [Byte], _ ikm: [Byte]) -> [Byte]

        /// `HKDF-Expand(PRK, info, length) -> OKM`.
        public let expand: (_ prk: [Byte], _ info: [Byte], _ length: Int) -> [Byte]

        /// Creates a key-schedule witness from hash and HKDF primitives.
        ///
        /// - Parameters:
        ///   - hashLength: The hash output length in bytes.
        ///   - hash: The cipher-suite hash function.
        ///   - extract: `HKDF-Extract`.
        ///   - expand: `HKDF-Expand` with an output-length knob.
        public init(
            hashLength: Int,
            hash: @escaping ([Byte]) -> [Byte],
            extract: @escaping (_ salt: [Byte], _ ikm: [Byte]) -> [Byte],
            expand: @escaping (_ prk: [Byte], _ info: [Byte], _ length: Int) -> [Byte]
        ) {
            self.hashLength = hashLength
            self.hash = hash
            self.extract = extract
            self.expand = expand
        }
    }
}
