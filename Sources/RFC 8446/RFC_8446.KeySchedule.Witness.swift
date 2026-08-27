public import Binary_Serializable

extension RFC_8446.KeySchedule {

    public struct Witness {

        public let hashLength: Int

        public let hash: ([Byte]) -> [Byte]

        public let extract: (_ salt: [Byte], _ ikm: [Byte]) -> [Byte]

        public let expand: (_ prk: [Byte], _ info: [Byte], _ length: Int) -> [Byte]

        public init(
            hashLength: Int,
            hash: @escaping ([Byte]) -> [Byte],
            extract: @escaping (_ salt: [Byte], _ ikm: [Byte]) -> [Byte],
            expand: @escaping (_ prk: [Byte], _ info: [Byte], _ length: Int) -> [Byte]
        ) {
            self.hashLength = hashLength
            self.hash = hash
            self.extract = extract
            self.expand = expand
        }
    }
}
