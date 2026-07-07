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

import RFC_8446
import RFC_8446_Standard_Library_Integration
import Testing

@Suite("RFC 8446 Record UInt8 forwarder")
struct RFC_8446_Record_UInt8_Tests {
    @Test
    func `forwarder agrees with primary byte-domain construction`() throws {
        let uint8Fragment: [UInt8] = [1, 2, 3, 4]
        let record = try RFC_8446.Record(contentType: .handshake, fragment: uint8Fragment)

        #expect(record.contentType == .handshake)
        #expect(record.legacyVersion == .legacy)
        #expect(record.fragment.count == 4)

        // Round-trip equality with [Byte] primary path
        let byteFragment: [Byte] = uint8Fragment.map(Byte.init)
        let primaryRecord = try RFC_8446.Record(contentType: .handshake, fragment: byteFragment)
        #expect(record == primaryRecord)
    }

    @Test
    func `forwarder rejects oversized fragment`() {
        let largeFragment = Array(repeating: UInt8(0), count: 16385)

        #expect(throws: RFC_8446.Record.Error.self) {
            try RFC_8446.Record(contentType: .applicationData, fragment: largeFragment)
        }
    }
}
