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

@Suite("RFC 8446 Handshake.Message UInt8 forwarder")
struct RFC_8446_Handshake_Message_UInt8_Tests {
    @Test
    func `forwarder agrees with primary byte-domain construction`() {
        let uint8Body: [UInt8] = [1, 2, 3, 4, 5]
        let message = try! RFC_8446.Handshake.Message(type: .clientHello, body: uint8Body)
        #expect(message.type == .clientHello)
        #expect(message.body.count == 5)

        // Round-trip equality with [Byte] primary path
        let byteBody: [Byte] = uint8Body.map(Byte.init)
        let primaryMessage = try! RFC_8446.Handshake.Message(type: .clientHello, body: byteBody)
        #expect(message == primaryMessage)
    }

    @Test
    func `forwarder serializes identically to byte-domain primary`() {
        let uint8Body: [UInt8] = [1, 2, 3, 4, 5]
        let message = try! RFC_8446.Handshake.Message(type: .clientHello, body: uint8Body)

        var buffer: [Byte] = []
        RFC_8446.Handshake.Message.serialize(message, into: &buffer)

        #expect(buffer.count == 9)  // 1 type + 3 length + 5 body
        #expect(buffer[0] == 1)  // client_hello
        #expect(buffer[1] == 0)  // length high
        #expect(buffer[2] == 0)  // length mid
        #expect(buffer[3] == 5)  // length low
    }
}
