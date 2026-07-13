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

// RFC_8446.KeySchedule.Derivation.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1: Key Schedule

public import Binary_Serializable_Primitives

extension RFC_8446.KeySchedule {
    /// `HKDF-Extract(salt, IKM) -> PRK`, via the witness.
    public static func extract(
        _ witness: Witness,
        salt: [Byte],
        ikm: [Byte]
    ) -> [Byte] {
        witness.extract(salt, ikm)
    }

    /// `HKDF-Expand-Label(Secret, Label, Context, Length)`.
    ///
    /// Builds the ``HkdfLabel`` (prepending the `"tls13 "` prefix to `label`)
    /// and feeds it to `HKDF-Expand` via the witness.
    public static func expandLabel(
        _ witness: Witness,
        secret: [Byte],
        label: some StringProtocol,
        context: [Byte],
        length: Int
    ) -> [Byte] {
        let hkdfLabel = HkdfLabel(length: UInt16(length), label: label, context: context)
        return witness.expand(secret, hkdfLabel.bytes, length)
    }

    /// `Derive-Secret(Secret, Label, Messages)` where the transcript hash is
    /// already computed.
    public static func deriveSecret(
        _ witness: Witness,
        secret: [Byte],
        label: some StringProtocol,
        transcriptHash: [Byte]
    ) -> [Byte] {
        expandLabel(
            witness,
            secret: secret,
            label: label,
            context: transcriptHash,
            length: witness.hashLength
        )
    }

    /// `Derive-Secret(Secret, Label, Messages)` over raw handshake-message
    /// bytes, hashing them via the witness first.
    public static func deriveSecret(
        _ witness: Witness,
        secret: [Byte],
        label: some StringProtocol,
        messages: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: secret, label: label, transcriptHash: witness.hash(messages))
    }

    /// A string of `Hash.length` zero bytes (the "0" input of the schedule).
    public static func zeros(_ witness: Witness) -> [Byte] {
        Array(repeating: Byte(0), count: witness.hashLength)
    }
}
