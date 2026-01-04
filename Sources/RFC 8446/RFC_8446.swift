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

// RFC_8446.swift
// swift-rfc-8446
//
// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3 (August 2018)
// https://www.rfc-editor.org/rfc/rfc8446.html
//
// This package implements TLS 1.3 protocol types as defined by RFC 8446.

/// RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
///
/// This namespace contains types for TLS 1.3 as defined in RFC 8446 from August 2018.
/// TLS 1.3 provides cryptographic security for communications over TCP.
///
/// ## Key Types
///
/// - ``ProtocolVersion``: TLS version identifiers
/// - ``Record``: TLS record layer
/// - ``ContentType``: Record content types
/// - ``Handshake``: Handshake protocol types
/// - ``CipherSuite``: Supported cipher suites
/// - ``Alert``: Alert protocol types
/// - ``Extension``: TLS extension types
///
/// ## Protocol Structure
///
/// TLS 1.3 consists of two main layers:
/// 1. **Record Protocol**: Provides confidentiality and integrity
/// 2. **Handshake Protocol**: Negotiates parameters and authenticates peers
///
/// ## Example
///
/// ```swift
/// // Create a TLS record
/// let record = try RFC_8446.Record(
///     contentType: .handshake,
///     fragment: handshakeData
/// )
///
/// // Serialize to wire format
/// var buffer: [UInt8] = []
/// RFC_8446.Record.serialize(record, into: &buffer)
/// ```
///
/// ## See Also
///
/// - [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
/// - [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) for ALPN
public enum RFC_8446 {}
