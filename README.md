# swift-rfc-8446

Use this package when you build or parse TLS 1.3 wire structures, or derive TLS 1.3 secrets, and bring your own cryptography. Start from `RFC_8446.Record` for the record layer, `RFC_8446.Handshake.Message` and the message types under `RFC_8446.Handshake`, such as `RFC_8446.Handshake.ClientHello`, for the handshake, and `RFC_8446.KeySchedule` for secrets. It doesn't run a handshake, protect records or check signatures. Certificate entries carry the certificate as opaque bytes; to read them, use swift-rfc-5280.

## Laws

- Every structure serializes to the exact bytes of RFC 8446, and the RFC 8448 example handshake parses and serializes back byte for byte.
- Building a value checks each length bound of the RFC's wire syntax and throws when one is broken, such as a random that isn't 32 bytes, an empty cipher suite list or an extension body over 65535 bytes. `RFC_8446.Extension.PreSharedKey.OfferedPsks` is an exception that accepts empty identity and binder lists, and `RFC_8446.KeySchedule.HkdfLabel` checks no bound.
- Parsing a message body or extension body must use up every byte. Too few bytes fail as truncated, and bytes left over fail as trailing data. A handshake message's declared length must equal the bytes that follow its header.
- Code points the package doesn't name, such as an unknown cipher suite, extension type or group, are kept as raw values. Extensions keep their order, so unknown ones survive a parse and serialize.
- Building a record sets the legacy version to TLS 1.2 (`0x0303`) and refuses a fragment over 16384 bytes. Parsing a record allows up to 16640 bytes, the ciphertext limit, and reads only the first record in the input.
- A `RFC_8446.Handshake.ServerHello` is a HelloRetryRequest exactly when its random is the fixed value of `RFC_8446.Handshake.ServerHello.helloRetryRequestRandom`.
- `RFC_8446.KeySchedule` does no cryptography itself. You pass a `RFC_8446.KeySchedule.Witness` with the hash, HKDF-Extract and HKDF-Expand for the cipher suite's hash. Its extract must be HMAC keyed by the salt, because Finished verify data is computed through it.
- Every label is prefixed with `tls13 ` before expansion. Without a PSK, the early secret uses a string of zeros as long as the hash.
- `RFC_8446.KeySchedule.Transcript` keeps the bytes you append, with a `RFC_8446.Handshake.Message` appended whole, four-byte header included. It hashes them only when asked.
