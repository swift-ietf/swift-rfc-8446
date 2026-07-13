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

// RFC_8446.KeySchedule.Stages.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1-7.3: Key Schedule stages

public import Binary_Serializable_Primitives

extension RFC_8446.KeySchedule {

    // MARK: - Early Secret stage

    /// `Early Secret = HKDF-Extract(0, PSK)`.
    ///
    /// If no PSK is in use, a `Hash.length` string of zeros is used as the IKM.
    public static func earlySecret(_ witness: Witness, psk: [Byte]? = nil) -> [Byte] {
        extract(witness, salt: zeros(witness), ikm: psk ?? zeros(witness))
    }

    /// `binder_key = Derive-Secret(Early Secret, "ext binder" | "res binder", "")`.
    public static func binderKey(
        _ witness: Witness,
        earlySecret: [Byte],
        isExternal: Bool
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: earlySecret,
            label: isExternal ? Label.externalBinder : Label.resumptionBinder,
            transcriptHash: witness.hash([])
        )
    }

    /// `client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic", ClientHello)`.
    public static func clientEarlyTrafficSecret(
        _ witness: Witness,
        earlySecret: [Byte],
        clientHello: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: earlySecret, label: Label.clientEarlyTraffic, messages: clientHello)
    }

    /// `early_exporter_master_secret = Derive-Secret(Early Secret, "e exp master", ClientHello)`.
    public static func earlyExporterMasterSecret(
        _ witness: Witness,
        earlySecret: [Byte],
        clientHello: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: earlySecret, label: Label.earlyExporterMaster, messages: clientHello)
    }

    // MARK: - Derive-Secret "derived" bridge

    /// `Derive-Secret(Secret, "derived", "")` — the bridge between Extract stages.
    public static func derivedSecret(_ witness: Witness, secret: [Byte]) -> [Byte] {
        deriveSecret(witness, secret: secret, label: Label.derived, transcriptHash: witness.hash([]))
    }

    // MARK: - Handshake Secret stage

    /// `Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), (EC)DHE)`.
    public static func handshakeSecret(
        _ witness: Witness,
        previousDerived: [Byte],
        sharedSecret: [Byte]
    ) -> [Byte] {
        extract(witness, salt: previousDerived, ikm: sharedSecret)
    }

    /// `client_handshake_traffic_secret = Derive-Secret(Handshake Secret, "c hs traffic", CH...SH)`.
    public static func clientHandshakeTrafficSecret(
        _ witness: Witness,
        handshakeSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: handshakeSecret, label: Label.clientHandshakeTraffic, transcriptHash: transcriptHash)
    }

    /// `server_handshake_traffic_secret = Derive-Secret(Handshake Secret, "s hs traffic", CH...SH)`.
    public static func serverHandshakeTrafficSecret(
        _ witness: Witness,
        handshakeSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: handshakeSecret, label: Label.serverHandshakeTraffic, transcriptHash: transcriptHash)
    }

    // MARK: - Master Secret stage

    /// `Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)`.
    public static func masterSecret(_ witness: Witness, previousDerived: [Byte]) -> [Byte] {
        extract(witness, salt: previousDerived, ikm: zeros(witness))
    }

    /// `client_application_traffic_secret_0 = Derive-Secret(Master Secret, "c ap traffic", CH...server Finished)`.
    public static func clientApplicationTrafficSecret0(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: masterSecret, label: Label.clientApplicationTraffic, transcriptHash: transcriptHash)
    }

    /// `server_application_traffic_secret_0 = Derive-Secret(Master Secret, "s ap traffic", CH...server Finished)`.
    public static func serverApplicationTrafficSecret0(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: masterSecret, label: Label.serverApplicationTraffic, transcriptHash: transcriptHash)
    }

    /// `exporter_master_secret = Derive-Secret(Master Secret, "exp master", CH...server Finished)`.
    public static func exporterMasterSecret(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: masterSecret, label: Label.exporterMaster, transcriptHash: transcriptHash)
    }

    /// `resumption_master_secret = Derive-Secret(Master Secret, "res master", CH...client Finished)`.
    public static func resumptionMasterSecret(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: masterSecret, label: Label.resumptionMaster, transcriptHash: transcriptHash)
    }

    // MARK: - Finished / traffic key expansions (Section 7.3, 4.4.4)

    /// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)`.
    public static func finishedKey(_ witness: Witness, baseKey: [Byte]) -> [Byte] {
        expandLabel(witness, secret: baseKey, label: Label.finished, context: [], length: witness.hashLength)
    }

    /// `verify_data = HMAC(finished_key, transcriptHash)`.
    ///
    /// HMAC and `HKDF-Extract` are the same primitive (`HKDF-Extract(salt, IKM)
    /// = HMAC(salt, IKM)`), so the finished MAC is computed through the
    /// witness's `extract` keyed by `finishedKey`.
    public static func finishedVerifyData(
        _ witness: Witness,
        finishedKey: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        extract(witness, salt: finishedKey, ikm: transcriptHash)
    }

    /// `[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)`.
    public static func writeKey(_ witness: Witness, secret: [Byte], keyLength: Int) -> [Byte] {
        expandLabel(witness, secret: secret, label: Label.key, context: [], length: keyLength)
    }

    /// `[sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)`.
    public static func writeIV(_ witness: Witness, secret: [Byte], ivLength: Int) -> [Byte] {
        expandLabel(witness, secret: secret, label: Label.iv, context: [], length: ivLength)
    }

    // MARK: - Updates and resumption (Section 7.2, 4.6.1)

    /// `application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)`.
    public static func nextApplicationTrafficSecret(_ witness: Witness, secret: [Byte]) -> [Byte] {
        expandLabel(witness, secret: secret, label: Label.trafficUpdate, context: [], length: witness.hashLength)
    }

    /// Per-ticket PSK: `HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`.
    public static func resumptionPSK(
        _ witness: Witness,
        resumptionMasterSecret: [Byte],
        ticketNonce: [Byte]
    ) -> [Byte] {
        expandLabel(witness, secret: resumptionMasterSecret, label: Label.resumption, context: ticketNonce, length: witness.hashLength)
    }
}
