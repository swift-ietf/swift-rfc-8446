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

// RFC_8446.Wire.swift
// swift-rfc-8446
//
// RFC 8446 Section 3: Presentation Language
//
// Internal home for the TLS presentation-language codec primitives
// (uint8/uint16/uint24-length-prefixed vectors, big-endian integers). All
// typed handshake and extension payloads route their byte-level reads and
// writes through here so the length-prefix discipline lives in ONE place
// per [IMPL-060]; there is no per-file duplication of the vector encoding.

extension RFC_8446 {
    /// Internal TLS presentation-language codec namespace.
    ///
    /// RFC 8446 Section 3 defines a small presentation language whose only
    /// composite forms are fixed-width big-endian integers and
    /// length-prefixed opaque vectors (`opaque x<lo..hi>`). ``Wire`` centralizes
    /// the reading (``Wire/Reader``) and writing (append helpers) of those forms.
    enum Wire {}
}
