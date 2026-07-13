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

// RFC_8446.KeySchedule.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1: Key Schedule

extension RFC_8446 {
    /// TLS 1.3 key schedule SHAPES (crypto-free).
    ///
    /// This namespace models the *structure* of the RFC 8446 Section 7.1 key
    /// schedule — the `HkdfLabel` wire form (``HkdfLabel``), the label
    /// vocabulary (``Label``), the transcript plumbing (``Transcript``), and the
    /// derivation/stage functions — WITHOUT any cryptographic implementation.
    /// All hashing and HKDF enter through a caller-supplied ``Witness`` whose
    /// closures perform the actual `Hash`, `HKDF-Extract`, and `HKDF-Expand`.
    /// The core target therefore never learns that cryptography exists.
    ///
    /// ## The Schedule (Section 7.1)
    ///
    /// ```
    ///              0
    ///              |
    ///              v
    ///    PSK ->  HKDF-Extract = Early Secret
    ///              |
    ///              +-----> Derive-Secret(., "ext binder" | "res binder", "")
    ///              +-----> Derive-Secret(., "c e traffic", ClientHello)
    ///              +-----> Derive-Secret(., "e exp master", ClientHello)
    ///              v
    ///        Derive-Secret(., "derived", "")
    ///              |
    ///              v
    ///    (EC)DHE -> HKDF-Extract = Handshake Secret
    ///              |
    ///              +-----> Derive-Secret(., "c hs traffic", CH...SH)
    ///              +-----> Derive-Secret(., "s hs traffic", CH...SH)
    ///              v
    ///        Derive-Secret(., "derived", "")
    ///              |
    ///              v
    ///    0 -> HKDF-Extract = Master Secret
    ///              |
    ///              +-----> Derive-Secret(., "c ap traffic", CH...server Finished)
    ///              +-----> Derive-Secret(., "s ap traffic", CH...server Finished)
    ///              +-----> Derive-Secret(., "exp master", CH...server Finished)
    ///              +-----> Derive-Secret(., "res master", CH...client Finished)
    /// ```
    ///
    /// ## The HKDF Functions (Section 7.1)
    ///
    /// ```
    /// HKDF-Expand-Label(Secret, Label, Context, Length) =
    ///      HKDF-Expand(Secret, HkdfLabel, Length)
    ///
    /// Derive-Secret(Secret, Label, Messages) =
    ///      HKDF-Expand-Label(Secret, Label,
    ///                        Transcript-Hash(Messages), Hash.length)
    /// ```
    public enum KeySchedule {}
}
