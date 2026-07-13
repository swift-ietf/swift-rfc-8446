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

// RFC_8446.Extension.EarlyData.swift
// swift-rfc-8446
//
// RFC 8446 Section 4.2.10: Early Data Indication

extension RFC_8446.Extension {
    /// `early_data` extension namespace.
    ///
    /// The `extension_data` body is `select`ed on the enclosing handshake
    /// message type:
    ///
    /// ```
    /// struct {} Empty;
    ///
    /// struct {
    ///     select (Handshake.msg_type) {
    ///         case new_session_ticket:   uint32 max_early_data_size;
    ///         case client_hello:         Empty;
    ///         case encrypted_extensions: Empty;
    ///     };
    /// } EarlyDataIndication;
    /// ```
    ///
    /// - ``Indication`` is the empty ClientHello / EncryptedExtensions form.
    /// - ``Ticket`` is the NewSessionTicket `max_early_data_size` form.
    public enum EarlyData {
        /// The extension type shared by both forms (`early_data`).
        public static let extensionType: RFC_8446.Extension.ExtensionType = .earlyData
    }
}
