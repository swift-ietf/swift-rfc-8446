extension RFC_8446.KeySchedule {

    public enum Label {

        public static let derived = "derived"

        public static let externalBinder = "ext binder"

        public static let resumptionBinder = "res binder"

        public static let clientEarlyTraffic = "c e traffic"

        public static let earlyExporterMaster = "e exp master"

        public static let clientHandshakeTraffic = "c hs traffic"

        public static let serverHandshakeTraffic = "s hs traffic"

        public static let clientApplicationTraffic = "c ap traffic"

        public static let serverApplicationTraffic = "s ap traffic"

        public static let exporterMaster = "exp master"

        public static let resumptionMaster = "res master"

        public static let finished = "finished"

        public static let key = "key"

        public static let iv = "iv"

        public static let trafficUpdate = "traffic upd"

        public static let resumption = "resumption"
    }
}
