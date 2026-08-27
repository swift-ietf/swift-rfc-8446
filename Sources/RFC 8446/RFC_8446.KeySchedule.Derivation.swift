public import Binary_Serializable

extension RFC_8446.KeySchedule {

    public static func extract(
        _ witness: Witness,
        salt: [Byte],
        ikm: [Byte]
    ) -> [Byte] {
        witness.extract(salt, ikm)
    }

    public static func expandLabel(
        _ witness: Witness,
        secret: [Byte],
        label: some StringProtocol,
        context: [Byte],
        length: Int
    ) -> [Byte] {
        let hkdfLabel = HkdfLabel(length: UInt16(length), label: label, context: context)
        return witness.expand(secret, hkdfLabel.bytes, length)
    }

    public static func deriveSecret(
        _ witness: Witness,
        secret: [Byte],
        label: some StringProtocol,
        transcriptHash: [Byte]
    ) -> [Byte] {
        expandLabel(
            witness,
            secret: secret,
            label: label,
            context: transcriptHash,
            length: witness.hashLength
        )
    }

    public static func deriveSecret(
        _ witness: Witness,
        secret: [Byte],
        label: some StringProtocol,
        messages: [Byte]
    ) -> [Byte] {
        deriveSecret(witness, secret: secret, label: label, transcriptHash: witness.hash(messages))
    }

    public static func zeros(_ witness: Witness) -> [Byte] {
        Array(repeating: Byte(0), count: witness.hashLength)
    }
}
