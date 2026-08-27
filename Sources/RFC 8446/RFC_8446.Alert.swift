public import Binary_Serializable

extension RFC_8446 {

    public struct Alert: Sendable, Hashable, Codable {

        public let level: Level

        public let alertDescription: Description

        public init(level: Level, description: Description) {
            self.level = level
            self.alertDescription = description
        }
    }
}

extension RFC_8446.Alert: Binary.Serializable {
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ alert: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(Byte(alert.level.rawValue))
        buffer.append(Byte(alert.alertDescription.rawValue))
    }
}

extension RFC_8446.Alert {

    public static func fatal(_ description: Description) -> Self {
        Self(level: .fatal, description: description)
    }

    public static func warning(_ description: Description) -> Self {
        Self(level: .warning, description: description)
    }

    public static var closeNotify: Self {
        Self(level: .warning, description: .closeNotify)
    }
}
