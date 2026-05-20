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

// RFC_8446.Handshake.Message+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for `RFC_8446.Handshake.Message`. Primary
// byte-domain API lives in `RFC 8446`; this forwarder bridges stdlib callers
// carrying `[UInt8]` (e.g. handshake bodies pulled from network buffers,
// file-read frames) via `.map(Byte.init)`. Per [API-BYTE-007]
// (byte-discipline skill).

public import RFC_8446
internal import Byte_Primitives

extension RFC_8446.Handshake.Message {
    /// Stdlib-interop forwarder: construction from `[UInt8]` body.
    @_disfavoredOverload
    public init(type: RFC_8446.Handshake.MessageType, body: [UInt8]) {
        self.init(type: type, body: body.map(Byte.init))
    }
}
