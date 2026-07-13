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

// RFC_8446.KeySchedule.Label.swift
// swift-rfc-8446
//
// RFC 8446 Section 7.1: Key Schedule

extension RFC_8446.KeySchedule {
    /// The bare TLS 1.3 key-schedule labels (without the `"tls13 "` prefix).
    ///
    /// These are the `Label` arguments to `HKDF-Expand-Label` / `Derive-Secret`
    /// as spelled in RFC 8446 Section 7.1; ``HkdfLabel`` prepends the prefix.
    public enum Label {
        /// `"derived"` — the salt-derivation step between Extract stages.
        public static let derived = "derived"

        /// `"ext binder"` — binder key for externally provisioned PSKs.
        public static let externalBinder = "ext binder"

        /// `"res binder"` — binder key for resumption PSKs.
        public static let resumptionBinder = "res binder"

        /// `"c e traffic"` — client_early_traffic_secret.
        public static let clientEarlyTraffic = "c e traffic"

        /// `"e exp master"` — early_exporter_master_secret.
        public static let earlyExporterMaster = "e exp master"

        /// `"c hs traffic"` — client_handshake_traffic_secret.
        public static let clientHandshakeTraffic = "c hs traffic"

        /// `"s hs traffic"` — server_handshake_traffic_secret.
        public static let serverHandshakeTraffic = "s hs traffic"

        /// `"c ap traffic"` — client_application_traffic_secret_0.
        public static let clientApplicationTraffic = "c ap traffic"

        /// `"s ap traffic"` — server_application_traffic_secret_0.
        public static let serverApplicationTraffic = "s ap traffic"

        /// `"exp master"` — exporter_master_secret.
        public static let exporterMaster = "exp master"

        /// `"res master"` — resumption_master_secret.
        public static let resumptionMaster = "res master"

        /// `"finished"` — the finished_key expansion.
        public static let finished = "finished"

        /// `"key"` — the [sender]_write_key expansion (Section 7.3).
        public static let key = "key"

        /// `"iv"` — the [sender]_write_iv expansion (Section 7.3).
        public static let iv = "iv"

        /// `"traffic upd"` — the application_traffic_secret_N+1 update (Section 7.2).
        public static let trafficUpdate = "traffic upd"

        /// `"resumption"` — the per-ticket PSK derivation (Section 4.6.1).
        public static let resumption = "resumption"
    }
}
