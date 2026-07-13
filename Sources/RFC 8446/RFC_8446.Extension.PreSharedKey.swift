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

// RFC_8446.Extension.PreSharedKey.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.11: Pre-Shared Key Extension

extension RFC_8446.Extension {
    /// `pre_shared_key` extension namespace.
    ///
    /// The `extension_data` body is `select`ed on the enclosing handshake
    /// message type:
    ///
    /// ```
    /// struct {
    ///     select (Handshake.msg_type) {
    ///         case client_hello: OfferedPsks;
    ///         case server_hello: uint16 selected_identity;
    ///     };
    /// } PreSharedKeyExtension;
    /// ```
    ///
    /// - ``OfferedPsks`` is the ClientHello form (identities + binders).
    /// - ``ServerHello`` is the selected-identity form.
    /// - ``Identity`` is a single `PskIdentity`.
    public enum PreSharedKey {
        /// The extension type shared by both forms (`pre_shared_key`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .preSharedKey
    }
}
