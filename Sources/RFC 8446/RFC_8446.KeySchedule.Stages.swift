public import Binary_Serializable

extension RFC_8446.KeySchedule {

    public static func earlySecret(_ witness: Witness, psk: [Byte]? = nil) -> [Byte] {
        extract(witness, salt: zeros(witness), ikm: psk ?? zeros(witness))
    }

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

    public static func clientEarlyTrafficSecret(
        _ witness: Witness,
        earlySecret: [Byte],
        clientHello: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: earlySecret,
            label: Label.clientEarlyTraffic,
            messages: clientHello
        )
    }

    public static func earlyExporterMasterSecret(
        _ witness: Witness,
        earlySecret: [Byte],
        clientHello: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: earlySecret,
            label: Label.earlyExporterMaster,
            messages: clientHello
        )
    }

    public static func derivedSecret(_ witness: Witness, secret: [Byte]) -> [Byte] {
        deriveSecret(
            witness,
            secret: secret,
            label: Label.derived,
            transcriptHash: witness.hash([])
        )
    }

    public static func handshakeSecret(
        _ witness: Witness,
        previousDerived: [Byte],
        sharedSecret: [Byte]
    ) -> [Byte] {
        extract(witness, salt: previousDerived, ikm: sharedSecret)
    }

    public static func clientHandshakeTrafficSecret(
        _ witness: Witness,
        handshakeSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: handshakeSecret,
            label: Label.clientHandshakeTraffic,
            transcriptHash: transcriptHash
        )
    }

    public static func serverHandshakeTrafficSecret(
        _ witness: Witness,
        handshakeSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: handshakeSecret,
            label: Label.serverHandshakeTraffic,
            transcriptHash: transcriptHash
        )
    }

    public static func masterSecret(_ witness: Witness, previousDerived: [Byte]) -> [Byte] {
        extract(witness, salt: previousDerived, ikm: zeros(witness))
    }

    public static func clientApplicationTrafficSecret0(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: masterSecret,
            label: Label.clientApplicationTraffic,
            transcriptHash: transcriptHash
        )
    }

    public static func serverApplicationTrafficSecret0(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: masterSecret,
            label: Label.serverApplicationTraffic,
            transcriptHash: transcriptHash
        )
    }

    public static func exporterMasterSecret(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: masterSecret,
            label: Label.exporterMaster,
            transcriptHash: transcriptHash
        )
    }

    public static func resumptionMasterSecret(
        _ witness: Witness,
        masterSecret: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        deriveSecret(
            witness,
            secret: masterSecret,
            label: Label.resumptionMaster,
            transcriptHash: transcriptHash
        )
    }

    public static func finishedKey(_ witness: Witness, baseKey: [Byte]) -> [Byte] {
        expandLabel(
            witness,
            secret: baseKey,
            label: Label.finished,
            context: [],
            length: witness.hashLength
        )
    }

    public static func finishedVerifyData(
        _ witness: Witness,
        finishedKey: [Byte],
        transcriptHash: [Byte]
    ) -> [Byte] {
        extract(witness, salt: finishedKey, ikm: transcriptHash)
    }

    public static func writeKey(_ witness: Witness, secret: [Byte], keyLength: Int) -> [Byte] {
        expandLabel(witness, secret: secret, label: Label.key, context: [], length: keyLength)
    }

    public static func writeIV(_ witness: Witness, secret: [Byte], ivLength: Int) -> [Byte] {
        expandLabel(witness, secret: secret, label: Label.iv, context: [], length: ivLength)
    }

    public static func nextApplicationTrafficSecret(_ witness: Witness, secret: [Byte]) -> [Byte] {
        expandLabel(
            witness,
            secret: secret,
            label: Label.trafficUpdate,
            context: [],
            length: witness.hashLength
        )
    }

    public static func resumptionPSK(
        _ witness: Witness,
        resumptionMasterSecret: [Byte],
        ticketNonce: [Byte]
    ) -> [Byte] {
        expandLabel(
            witness,
            secret: resumptionMasterSecret,
            label: Label.resumption,
            context: ticketNonce,
            length: witness.hashLength
        )
    }
}
