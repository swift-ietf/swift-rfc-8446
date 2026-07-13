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

// RFC_8446.Extension.SupportedVersions.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.1: Supported Versions

extension RFC_8446.Extension {
    /// `supported_versions` extension namespace.
    ///
    /// The `extension_data` body is `select`ed on the enclosing handshake
    /// message type, so the two forms are modeled as distinct types:
    ///
    /// ```
    /// struct {
    ///     select (Handshake.msg_type) {
    ///         case client_hello:
    ///              ProtocolVersion versions<2..254>;
    ///         case server_hello: /* and HelloRetryRequest */
    ///              ProtocolVersion selected_version;
    ///     };
    /// } SupportedVersions;
    /// ```
    ///
    /// - ``ClientHello`` carries the list of offered versions.
    /// - ``ServerHello`` carries the single selected version.
    public enum SupportedVersions {
        /// The extension type shared by both forms (`supported_versions`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .supportedVersions
    }
}
