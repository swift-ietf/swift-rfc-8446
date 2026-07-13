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

// RFC_8446.Extension.KeyShare.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.8: Key Share

extension RFC_8446.Extension {
    /// `key_share` extension namespace.
    ///
    /// The `extension_data` body is `select`ed on the enclosing handshake
    /// message type, so the three forms are modeled as distinct types:
    ///
    /// - ``ClientHello`` — `KeyShareClientHello { KeyShareEntry client_shares<0..2^16-1>; }`
    /// - ``ServerHello`` — `KeyShareServerHello { KeyShareEntry server_share; }`
    /// - ``HelloRetryRequest`` — `KeyShareHelloRetryRequest { NamedGroup selected_group; }`
    ///
    /// All forms are built from ``Entry`` (`KeyShareEntry`).
    public enum KeyShare {
        /// The extension type shared by all forms (`key_share`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .keyShare
    }
}
