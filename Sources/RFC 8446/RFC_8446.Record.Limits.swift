extension RFC_8446.Record {

    public enum Limits {

        public static let maxPlaintextLength = 16384

        public static let maxCiphertextLength = 16384 + 256

        public static let headerSize = 5
    }
}
