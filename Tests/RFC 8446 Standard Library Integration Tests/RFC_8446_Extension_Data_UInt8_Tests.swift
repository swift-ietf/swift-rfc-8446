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

import Testing
import RFC_8446
import RFC_8446_Standard_Library_Integration

@Suite("RFC 8446 Extension.Data UInt8 forwarder")
struct RFC_8446_Extension_Data_UInt8_Tests {
    @Test
    func `forwarder agrees with primary byte-domain construction`() {
        let uint8Data: [UInt8] = [0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
        let ext = RFC_8446.Extension.Data(type: .serverName, data: uint8Data)
        #expect(ext.type == .serverName)
        #expect(ext.data.count == 7)

        // Round-trip equality with [Byte] primary path
        let byteData: [Byte] = uint8Data.map(Byte.init)
        let primaryExt = RFC_8446.Extension.Data(type: .serverName, data: byteData)
        #expect(ext == primaryExt)
    }

    @Test
    func `forwarder serializes identically to byte-domain primary`() {
        let uint8Data: [UInt8] = [0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
        let ext = RFC_8446.Extension.Data(type: .serverName, data: uint8Data)

        var buffer: [Byte] = []
        RFC_8446.Extension.Data.serialize(ext, into: &buffer)

        #expect(buffer.count == 11) // 2 type + 2 length + 7 data
        #expect(buffer[0] == 0) // type high
        #expect(buffer[1] == 0) // type low (server_name = 0)
    }
}
