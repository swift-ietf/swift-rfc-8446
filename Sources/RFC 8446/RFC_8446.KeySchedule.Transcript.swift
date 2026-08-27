public import Binary_Serializable

extension RFC_8446.KeySchedule {

    public struct Transcript: Sendable, Hashable {

        public private(set) var messages: [Byte]

        public init() {
            self.messages = []
        }

        public init(messages: [Byte]) {
            self.messages = messages
        }

        public mutating func append(_ bytes: [Byte]) {
            messages.append(contentsOf: bytes)
        }

        public mutating func append(_ message: RFC_8446.Handshake.Message) {
            messages.append(contentsOf: message.bytes)
        }

        public func hash(using witness: RFC_8446.KeySchedule.Witness) -> [Byte] {
            witness.hash(messages)
        }
    }
}
