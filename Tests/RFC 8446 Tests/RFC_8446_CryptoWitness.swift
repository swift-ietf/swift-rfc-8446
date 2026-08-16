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
//
// TEST-TARGET-ONLY crypto adapter. This file adapts blessed apple/swift-crypto
// INTO the crypto-free `RFC_8446.KeySchedule.Witness` closures. The core
// "RFC 8446" target never sees swift-crypto: the witness seam is the only
// contact point, and it flows one way (swift-crypto -> witness). HKDF is built
// over swift-crypto's real HMAC-SHA256 per RFC 5869; no primitive is
// hand-rolled.

import Crypto
import Foundation

@testable import RFC_8446

extension RFC_8446.KeySchedule.Witness {
    /// A SHA-256 + HKDF witness backed by swift-crypto.
    ///
    /// Computed (not a stored `static let`) because ``RFC_8446/KeySchedule/Witness``
    /// carries non-`Sendable` closures by design; a fresh value per access keeps
    /// this free of global shared mutable state under strict concurrency.
    static var sha256: RFC_8446.KeySchedule.Witness {
        RFC_8446.KeySchedule.Witness(
            hashLength: 32,
            hash: { message in
                let digest = SHA256.hash(data: Data(message.map(\.underlying)))
                return digest.map(Byte.init)
            },
            extract: { salt, ikm in
                // HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM).
                let key = SymmetricKey(data: Data(salt.map(\.underlying)))
                let mac = HMAC<SHA256>.authenticationCode(
                    for: Data(ikm.map(\.underlying)),
                    using: key
                )
                return Array(mac).map(Byte.init)
            },
            expand: { prk, info, length in
                // RFC 5869 HKDF-Expand over swift-crypto's HMAC-SHA256.
                let key = SymmetricKey(data: Data(prk.map(\.underlying)))
                let infoBytes = info.map(\.underlying)
                var okm: [UInt8] = []
                var previousBlock: [UInt8] = []
                var counter: UInt8 = 1
                while okm.count < length {
                    var input = previousBlock
                    input.append(contentsOf: infoBytes)
                    input.append(counter)
                    let block = HMAC<SHA256>.authenticationCode(for: Data(input), using: key)
                    previousBlock = Array(block)
                    okm.append(contentsOf: previousBlock)
                    counter &+= 1
                }
                return okm.prefix(length).map(Byte.init)
            }
        )
    }
}
