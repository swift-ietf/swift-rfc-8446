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

// RFC_8446.Record+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for `RFC_8446.Record`. Primary byte-domain
// API lives in `RFC 8446`; this forwarder bridges stdlib callers carrying
// `[UInt8]` (e.g. record fragments pulled from network buffers, file-read
// frames) via `.map(Byte.init)`. Per [API-BYTE-007] (byte-discipline skill).

internal import Byte_Primitives
public import RFC_8446

extension RFC_8446.Record {
    /// Stdlib-interop forwarder: construction from `[UInt8]` fragment.
    @_disfavoredOverload
    public init(
        contentType: RFC_8446.ContentType,
        fragment: [UInt8]
    ) throws(RFC_8446.Record.Error) {
        try self.init(contentType: contentType, fragment: fragment.map(Byte.init))
    }
}
