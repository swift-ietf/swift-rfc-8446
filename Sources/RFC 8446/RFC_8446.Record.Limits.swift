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

// RFC_8446.Record.Limits.swift
// swift-rfc-8446
//
// RFC 8446 Section 5.1: Record Layer

extension RFC_8446.Record {
    /// Record layer limits
    public enum Limits {
        /// Maximum plaintext fragment length (2^14 = 16384)
        public static let maxPlaintextLength = 16384

        /// Maximum ciphertext record length (2^14 + 256)
        public static let maxCiphertextLength = 16384 + 256

        /// Record header size (5 bytes)
        public static let headerSize = 5
    }
}
