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

// RFC_8446.Extension.Data+UInt8.swift
//
// Stdlib-interop UInt8 forwarder for `RFC_8446.Extension.Data`. Primary
// byte-domain API lives in `RFC 8446`; this forwarder bridges stdlib callers
// carrying `[UInt8]` (e.g. extension payloads pulled from network buffers,
// file-read frames) via `.lazy.map(Byte.init)`. Per [API-BYTE-007]
// (byte-discipline skill).

internal import Byte_Primitives
public import RFC_8446

extension RFC_8446.Extension.Data {
    /// Stdlib-interop forwarder: construction from `[UInt8]` data.
    @_disfavoredOverload
    public init(type: RFC_8446.Extension.ExtensionType, data: [UInt8]) {
        self.init(type: type, data: data.map(Byte.init))
    }
}
