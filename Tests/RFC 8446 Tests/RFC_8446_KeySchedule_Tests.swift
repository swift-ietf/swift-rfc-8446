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

import Binary_Serializable_Primitives
import Testing

@testable import RFC_8446

@Suite("RFC 8446 Key Schedule")
struct RFC_8446_KeySchedule_Tests {

    typealias KS = RFC_8446.KeySchedule

    // MARK: - HkdfLabel byte-exact shapes (RFC 8448 logged "info" values)

    @Suite("HkdfLabel byte-exact shapes")
    struct HkdfLabelShapes {
        @Test
        func `derived label matches logged info`() {
            let label = KS.HkdfLabel(
                length: 32,
                label: KS.Label.derived,
                context: RFC8448.emptyHash
            )
            #expect(label.bytes == RFC8448.derivedInfo)
            #expect(label.label == KS.HkdfLabel.prefix + hex("64 65 72 69 76 65 64"))  // "derived"
        }

        @Test
        func `c hs traffic label matches logged info`() {
            let label = KS.HkdfLabel(
                length: 32,
                label: KS.Label.clientHandshakeTraffic,
                context: RFC8448.handshakeTranscriptHash
            )
            #expect(label.bytes == RFC8448.clientHandshakeTrafficInfo)
        }

        @Test
        func `key label matches logged info`() {
            let label = KS.HkdfLabel(length: 16, label: KS.Label.key, context: [])
            #expect(label.bytes == RFC8448.keyInfo)
        }

        @Test
        func `iv label matches logged info`() {
            let label = KS.HkdfLabel(length: 12, label: KS.Label.iv, context: [])
            #expect(label.bytes == RFC8448.ivInfo)
        }

        @Test
        func `finished label matches logged info`() {
            let label = KS.HkdfLabel(length: 32, label: KS.Label.finished, context: [])
            #expect(label.bytes == RFC8448.finishedInfo)
        }

        @Test
        func `HkdfLabel round-trips through parse`() throws {
            let label = try KS.HkdfLabel(binary: RFC8448.derivedInfo)
            #expect(label.length == 32)
            #expect(label.context == RFC8448.emptyHash)
            #expect(label.bytes == RFC8448.derivedInfo)
        }
    }

    // MARK: - Full-chain key schedule (live SHA-256/HKDF witness over swift-crypto)

    @Suite("RFC 8448 full-chain derivation")
    struct FullChain {
        /// Fresh witness per access — the suite holds no non-`Sendable` state.
        var witness: RFC_8446.KeySchedule.Witness { RFC_8446.KeySchedule.Witness.sha256 }

        /// Transcript hash of ClientHello...ServerHello via the witness matches
        /// the value logged in RFC 8448.
        @Test
        func `transcript hash of ClientHello and ServerHello`() {
            var transcript = KS.Transcript()
            transcript.append(RFC8448.clientHello)
            transcript.append(RFC8448.serverHello)
            #expect(transcript.hash(using: witness) == RFC8448.handshakeTranscriptHash)
        }

        @Test
        // `master secret` is RFC 8446's normative vocabulary for this value;
        // renaming it would break correspondence with the specification.
        // swiftlint:disable:next inclusive_language
        func `early handshake and master secrets`() {
            let early = KS.earlySecret(witness)
            #expect(early == RFC8448.earlySecret)

            let derived1 = KS.derivedSecret(witness, secret: early)
            #expect(derived1 == RFC8448.derivedForHandshake)

            let handshake = KS.handshakeSecret(
                witness,
                previousDerived: derived1,
                sharedSecret: RFC8448.ecdheSharedSecret
            )
            #expect(handshake == RFC8448.handshakeSecret)

            let derived2 = KS.derivedSecret(witness, secret: handshake)
            #expect(derived2 == RFC8448.derivedForMaster)

            // `master secret` is RFC 8446's normative vocabulary for this value;
            // renaming it would break correspondence with the specification.
            // swiftlint:disable:next inclusive_language
            let master = KS.masterSecret(witness, previousDerived: derived2)
            #expect(master == RFC8448.masterSecret)
        }

        @Test
        func `handshake traffic secrets and write keys`() {
            let early = KS.earlySecret(witness)
            let derived1 = KS.derivedSecret(witness, secret: early)
            let handshake = KS.handshakeSecret(
                witness,
                previousDerived: derived1,
                sharedSecret: RFC8448.ecdheSharedSecret
            )

            var transcript = KS.Transcript()
            transcript.append(RFC8448.clientHello)
            transcript.append(RFC8448.serverHello)
            let hash = transcript.hash(using: witness)

            let clientHS = KS.clientHandshakeTrafficSecret(
                witness,
                handshakeSecret: handshake,
                transcriptHash: hash
            )
            #expect(clientHS == RFC8448.clientHandshakeTraffic)

            let serverHS = KS.serverHandshakeTrafficSecret(
                witness,
                handshakeSecret: handshake,
                transcriptHash: hash
            )
            #expect(serverHS == RFC8448.serverHandshakeTraffic)

            #expect(
                KS.writeKey(witness, secret: serverHS, keyLength: 16)
                    == RFC8448.serverHandshakeWriteKey
            )
            #expect(
                KS.writeIV(witness, secret: serverHS, ivLength: 12)
                    == RFC8448.serverHandshakeWriteIV
            )
        }

        @Test
        func `server Finished key and verify_data`() throws {
            let early = KS.earlySecret(witness)
            let derived1 = KS.derivedSecret(witness, secret: early)
            let handshake = KS.handshakeSecret(
                witness,
                previousDerived: derived1,
                sharedSecret: RFC8448.ecdheSharedSecret
            )
            var chSH = KS.Transcript()
            chSH.append(RFC8448.clientHello)
            chSH.append(RFC8448.serverHello)
            let serverHS = KS.serverHandshakeTrafficSecret(
                witness,
                handshakeSecret: handshake,
                transcriptHash: chSH.hash(using: witness)
            )

            let finishedKey = KS.finishedKey(witness, baseKey: serverHS)
            #expect(finishedKey == RFC8448.serverFinishedKey)

            // Transcript through CertificateVerify.
            var transcript = KS.Transcript()
            transcript.append(RFC8448.clientHello)
            transcript.append(RFC8448.serverHello)
            transcript.append(RFC8448.encryptedExtensions)
            transcript.append(RFC8448.certificate)
            transcript.append(RFC8448.certificateVerify)

            let verifyData = KS.finishedVerifyData(
                witness,
                finishedKey: finishedKey,
                transcriptHash: transcript.hash(using: witness)
            )
            #expect(verifyData == RFC8448.serverFinishedVerifyData)

            // The verify_data equals the parsed Finished payload.
            let message = try RFC_8446.Handshake.Message(binary: RFC8448.serverFinished)
            let finished = try RFC_8446.Handshake.Finished(binary: message.body)
            #expect(verifyData == finished.verifyData)
        }

        @Test
        func `application traffic secrets and write keys`() {
            let early = KS.earlySecret(witness)
            let derived1 = KS.derivedSecret(witness, secret: early)
            let handshake = KS.handshakeSecret(
                witness,
                previousDerived: derived1,
                sharedSecret: RFC8448.ecdheSharedSecret
            )
            let derived2 = KS.derivedSecret(witness, secret: handshake)
            // `master secret` is RFC 8446's normative vocabulary for this value;
            // renaming it would break correspondence with the specification.
            // swiftlint:disable:next inclusive_language
            let master = KS.masterSecret(witness, previousDerived: derived2)

            // Transcript through server Finished.
            var transcript = KS.Transcript()
            transcript.append(RFC8448.clientHello)
            transcript.append(RFC8448.serverHello)
            transcript.append(RFC8448.encryptedExtensions)
            transcript.append(RFC8448.certificate)
            transcript.append(RFC8448.certificateVerify)
            transcript.append(RFC8448.serverFinished)
            let hash = transcript.hash(using: witness)

            let clientAP = KS.clientApplicationTrafficSecret0(
                witness,
                masterSecret: master,
                transcriptHash: hash
            )
            #expect(clientAP == RFC8448.clientApplicationTraffic)

            let serverAP = KS.serverApplicationTrafficSecret0(
                witness,
                masterSecret: master,
                transcriptHash: hash
            )
            #expect(serverAP == RFC8448.serverApplicationTraffic)

            let exporter = KS.exporterMasterSecret(
                witness,
                masterSecret: master,
                transcriptHash: hash
            )
            #expect(exporter == RFC8448.exporterMaster)

            #expect(
                KS.writeKey(witness, secret: serverAP, keyLength: 16)
                    == RFC8448.serverApplicationWriteKey
            )
            #expect(
                KS.writeIV(witness, secret: serverAP, ivLength: 12)
                    == RFC8448.serverApplicationWriteIV
            )
        }

        @Test
        // `master secret` is RFC 8446's normative vocabulary for this value;
        // renaming it would break correspondence with the specification.
        // swiftlint:disable:next inclusive_language
        func `client Finished and resumption master secret`() {
            let early = KS.earlySecret(witness)
            let derived1 = KS.derivedSecret(witness, secret: early)
            let handshake = KS.handshakeSecret(
                witness,
                previousDerived: derived1,
                sharedSecret: RFC8448.ecdheSharedSecret
            )
            let derived2 = KS.derivedSecret(witness, secret: handshake)
            // `master secret` is RFC 8446's normative vocabulary for this value;
            // renaming it would break correspondence with the specification.
            // swiftlint:disable:next inclusive_language
            let master = KS.masterSecret(witness, previousDerived: derived2)

            var chSH = KS.Transcript()
            chSH.append(RFC8448.clientHello)
            chSH.append(RFC8448.serverHello)
            let clientHS = KS.clientHandshakeTrafficSecret(
                witness,
                handshakeSecret: handshake,
                transcriptHash: chSH.hash(using: witness)
            )

            // Client Finished is computed over the transcript through the
            // server Finished.
            var throughServerFinished = KS.Transcript()
            throughServerFinished.append(RFC8448.clientHello)
            throughServerFinished.append(RFC8448.serverHello)
            throughServerFinished.append(RFC8448.encryptedExtensions)
            throughServerFinished.append(RFC8448.certificate)
            throughServerFinished.append(RFC8448.certificateVerify)
            throughServerFinished.append(RFC8448.serverFinished)
            let hashThroughServerFinished = throughServerFinished.hash(using: witness)

            let clientFinishedKey = KS.finishedKey(witness, baseKey: clientHS)
            #expect(clientFinishedKey == RFC8448.clientFinishedKey)

            let clientVerify = KS.finishedVerifyData(
                witness,
                finishedKey: clientFinishedKey,
                transcriptHash: hashThroughServerFinished
            )
            #expect(clientVerify == RFC8448.clientFinishedVerifyData)

            // Resumption master secret is over the transcript through the
            // client Finished.
            var throughClientFinished = throughServerFinished
            throughClientFinished.append(RFC8448.clientFinished)
            let resumption = KS.resumptionMasterSecret(
                witness,
                masterSecret: master,
                transcriptHash: throughClientFinished.hash(using: witness)
            )
            #expect(resumption == RFC8448.resumptionMaster)
        }
    }
}
