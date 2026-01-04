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

// RFC_8446.Extension.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2: Extensions

extension RFC_8446 {
    /// TLS Extensions namespace
    ///
    /// Extensions allow additional functionality to be negotiated
    /// in the TLS handshake.
    ///
    /// ## Wire Format
    ///
    /// ```
    /// struct {
    ///     ExtensionType extension_type;
    ///     opaque extension_data<0..2^16-1>;
    /// } Extension;
    /// ```
    public enum Extension {}
}
