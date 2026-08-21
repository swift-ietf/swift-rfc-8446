import Crypto
import Foundation

@testable import RFC_8446

extension RFC_8446.KeySchedule.Witness {

    static var sha256: RFC_8446.KeySchedule.Witness {
        RFC_8446.KeySchedule.Witness(
            hashLength: 32,
            hash: { message in
                let digest = SHA256.hash(data: Data(message.map(\.underlying)))
                return digest.map(Byte.init)
            },
            extract: { salt, ikm in

                let key = SymmetricKey(data: Data(salt.map(\.underlying)))
                let mac = HMAC<SHA256>.authenticationCode(
                    for: Data(ikm.map(\.underlying)),
                    using: key
                )
                return Array(mac).map(Byte.init)
            },
            expand: { prk, info, length in

                let key = SymmetricKey(data: Data(prk.map(\.underlying)))
                let infoBytes = info.map(\.underlying)
                var okm: [UInt8] = []
                var previousBlock: [UInt8] = []
                var counter: UInt8 = 1
                while okm.count < length {
                    var input = previousBlock
                    input.append(contentsOf: infoBytes)
                    input.append(counter)
                    let block = HMAC<SHA256>.authenticationCode(for: Data(input), using: key)
                    previousBlock = Array(block)
                    okm.append(contentsOf: previousBlock)
                    counter &+= 1
                }
                return okm.prefix(length).map(Byte.init)
            }
        )
    }
}
