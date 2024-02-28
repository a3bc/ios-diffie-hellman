//
//  DiffieHellman.swift
//  A3BC Group
//

import Foundation
import BigInt

/**
 * Diffie–Hellman key exchange
 **/
final class DiffieHellman {
    /**
     * Diffie-Hellman key pair
     */
    struct DHKeyPair {
        var privateKey: Data
        var publicKey: Data

        init(privateKey: Data, publicKey: Data) {
            self.privateKey = privateKey
            self.publicKey = publicKey
        }
    }

    /// Generate a Diffie–Hellman key pair
    ///
    /// - Parameter modulus: Diffie-Hellman modulus P
    /// - Parameter base: Diffie-Hellman base G
    /// - Returns: DH key pair, or nil on error
    static func generateDhKeyPair(modulus: Data, base: Data) -> DHKeyPair? {
        let startDate = Date()

        // Modulus
        let modulusBigUInt = BigUInt(modulus)

        // Base
        let baseBigUInt = BigUInt(base)

        // Private key
        guard let privateKey = Crypto.randomBytes(length: 512) else {
            print("Error creating a random private key")
            return nil
        }
        let privateKeyBigUInt = BigUInt(privateKey)

        // Public key
        let publicKeyBigUInt = baseBigUInt.power(privateKeyBigUInt, modulus: modulusBigUInt)
        let publicKey = publicKeyBigUInt.serialize()

        // Create Diffie–Hellman key pair
        let dhKeypair = DHKeyPair(privateKey: privateKey, publicKey: publicKey)

        let executionTime = Date().timeIntervalSince(startDate) * 1000
        print("Diffie-Hellman time: \(executionTime) ms")

        return dhKeypair
    }

    /// Compute a shared secret based on local pair key (public/private) and remote public key
    ///
    /// - Parameter privateKey: Private key
    /// - Parameter remotePublicKey: Remote public key
    /// - Parameter modulus: Diffie-Hellman modulus P
    /// - Returns: the computed shared secret
    static func computeSharedSecret(privateKey: Data, remotePublicKey: Data, modulus: Data) -> Data {
        let startDate = Date()

        // Private key
        let privateKeyBigUInt = BigUInt(privateKey)

        // Remote public key
        let remotePublicKeyBigUInt = BigUInt(remotePublicKey)

        // Modulus
        let modulusBigUInt = BigUInt(modulus)

        // Shared secret
        let sharedSecretBigUInt = remotePublicKeyBigUInt.power(privateKeyBigUInt, modulus: modulusBigUInt)
        let sharedSecret = sharedSecretBigUInt.serialize()

        let executionTime = Date().timeIntervalSince(startDate) * 1000
        print(message: "DH time: \(executionTime) ms")

        return sharedSecret
    }
}
