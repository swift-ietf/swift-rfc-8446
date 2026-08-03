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
// Byte-exact test vectors transcribed from RFC 8448 Section 3 (Simple 1-RTT
// Handshake). https://www.rfc-editor.org/rfc/rfc8448.txt

@testable import RFC_8446

/// Decodes a whitespace-tolerant hex string into a byte-domain `[Byte]`.
func hex(_ string: String) -> [Byte] {
    var nibbles: [UInt8] = []
    for scalar in string.unicodeScalars {
        switch scalar {
        case "0"..."9": nibbles.append(UInt8(scalar.value - 0x30))
        case "a"..."f": nibbles.append(UInt8(scalar.value - 0x61 + 10))
        case "A"..."F": nibbles.append(UInt8(scalar.value - 0x41 + 10))
        default: continue  // skip whitespace and separators
        }
    }
    var result: [Byte] = []
    result.reserveCapacity(nibbles.count / 2)
    var index = 0
    while index + 1 < nibbles.count {
        result.append(Byte((nibbles[index] << 4) | nibbles[index + 1]))
        index += 2
    }
    return result
}

/// RFC 8448 Section 3 vectors.
enum RFC8448 {

    // MARK: - Full handshake messages (type + uint24 length + body)

    static let clientHello = hex(
        """
        01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff
        a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13
        02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00
        01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01
        03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4
        bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52
        9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
        03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02
        00 2d 00 02 01 01 00 1c 00 02 40 01
        """
    )

    static let serverHello = hex(
        """
        02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93
        0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33
        00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56
        d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
        """
    )

    static let encryptedExtensions = hex(
        """
        08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01
        01 01 02 01 03 01 04 00 1c 00 02 40 01 00 00 00 00
        """
    )

    static let certificate = hex(
        """
        0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30 82 01 15 a0 03 02 01
        02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c
        30 0a 06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36 30 37 33 30 30
        31 32 33 35 39 5a 17 0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e
        31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86
        48 86 f7 0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49
        8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3
        90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e
        aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e
        0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c
        8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28
        a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18 30 09 06 03
        55 1d 13 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d 06
        09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27
        6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36
        54 17 f2 ea e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a
        03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
        c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b
        84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29 ac
        91 87 b4 2b 4d e1 00 00
        """
    )

    static let certificateVerify = hex(
        """
        0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6 10 15
        b7 21 1f 82 4c d4 84 14 5a b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78
        e2 d3 3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3
        94 ca b6 d3 0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45
        9e 46 44 5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15
        2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3
        """
    )

    static let serverFinished = hex(
        """
        14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c
        30 95 72 cb 7f ff ee 54 54 b7 8f 07 18
        """
    )

    static let clientFinished = hex(
        """
        14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76
        94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61
        """
    )

    static let newSessionTicket = hex(
        """
        04 00 00 c9 00 00 00 1e fa d6 aa c5 02 00 00 00 b2 2c 03 5d 82 93 59
        ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa
        90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60
        97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f
        d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37
        25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c 5b
        3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 17 64 6f
        ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88
        e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00 04 00 00 04 00
        """
    )

    // MARK: - Key schedule secrets

    /// (EC)DHE shared secret (documented input to the Handshake Secret Extract).
    static let ecdheSharedSecret = hex(
        """
        8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63
        ef d4 62 72 90 0f 89 49 2d
        """
    )

    static let earlySecret = hex(
        """
        33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26
        60 e1 b2 2e 10 f1 70 f9 2a
        """
    )

    static let derivedForHandshake = hex(
        """
        6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25
        0c eb ea c3 57 6c 36 11 ba
        """
    )

    static let handshakeSecret = hex(
        """
        1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e
        d2 21 a9 f0 ca 04 3f be ac
        """
    )

    static let clientHandshakeTraffic = hex(
        """
        b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e
        96 00 74 6a 0e 27 a5 5a 21
        """
    )

    static let serverHandshakeTraffic = hex(
        """
        b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10
        5d 42 be fd 59 d3 91 ad 38
        """
    )

    static let derivedForMaster = hex(
        """
        43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4
        f1 2d d7 a0 bb 7c e2 54 b4
        """
    )

    static let masterSecret = hex(
        """
        18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79
        84 d5 a4 1d a8 d0 40 29 19
        """
    )

    static let serverHandshakeWriteKey = hex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")
    static let serverHandshakeWriteIV = hex("5d 31 3e b2 67 12 76 ee 13 00 0b 30")

    static let serverFinishedKey = hex(
        """
        00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f
        01 f2 88 a1 d8 cd c1 9f c8
        """
    )

    static let serverFinishedVerifyData = hex(
        """
        9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb
        7f ff ee 54 54 b7 8f 07 18
        """
    )

    static let clientApplicationTraffic = hex(
        """
        9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00
        87 f7 92 eb b7 c1 75 04 a5
        """
    )

    static let serverApplicationTraffic = hex(
        """
        a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b
        3a 4b 4f 1f 3f cb 63 16 43
        """
    )

    static let exporterMaster = hex(
        """
        fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5 0c 9a 3f 89 45 2f 68
        d8 ae 31 1b 43 09 d3 cf 50
        """
    )

    static let serverApplicationWriteKey = hex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56")
    static let serverApplicationWriteIV = hex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84")

    static let clientFinishedKey = hex(
        """
        b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8 3f 84 82 1d 1f 87 fd
        c7 d3 c7 5b 5a 7b 42 d9 c4
        """
    )

    static let clientFinishedVerifyData = hex(
        """
        a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9
        85 27 b6 42 f2 ed d5 ce 61
        """
    )

    static let resumptionMaster = hex(
        """
        7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf da f8 6c c8 56 23 1f
        2d 5a ba 46 c4 34 ec 19 6c
        """
    )

    // MARK: - HkdfLabel inputs (logged "info" values)

    /// SHA-256 of the empty string (transcript hash for "derived" / "finished").
    static let emptyHash = hex(
        """
        e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93
        4c a4 95 99 1b 78 52 b8 55
        """
    )

    /// Transcript hash of ClientHello...ServerHello.
    static let handshakeTranscriptHash = hex(
        """
        86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9
        5f 02 ed 06 3c f0 e1 ca d8
        """
    )

    static let derivedInfo = hex(
        """
        00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64 20 e3 b0 c4 42 98 fc
        1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78
        52 b8 55
        """
    )

    static let clientHandshakeTrafficInfo = hex(
        """
        00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72 61 66 66 69 63 20 86
        0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f
        02 ed 06 3c f0 e1 ca d8
        """
    )

    static let keyInfo = hex("00 10 09 74 6c 73 31 33 20 6b 65 79 00")
    static let ivInfo = hex("00 0c 08 74 6c 73 31 33 20 69 76 00")
    static let finishedInfo = hex("00 20 0e 74 6c 73 31 33 20 66 69 6e 69 73 68 65 64 00")
}
