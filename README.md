# ios-diffie-hellman
Diffie–Hellman key exchange for iOS

# Dependencies
BigInt https://github.com/attaswift/BigInt

# Structures
## DHKeyPair
Diffie-Hellman key pair composed of a private key and a public key.

# Functions
## generateDhKeyPair(modulus: Data, base: Data) -> DHKeyPair?
Generate a Diffie–Hellman key pair.
Parameters:
- modulus: Diffie-Hellman modulus P
- base: Diffie-Hellman base G
Return a DH key pair, or nil on error

## computeSharedSecret(privateKey: Data, remotePublicKey: Data, modulus: Data) -> Data
Compute a shared secret based on local pair key (public/private) and remote public key.
Parameters:
- privateKey: Private key
- remotePublicKey: Remote public key
- modulus: Diffie-Hellman modulus P
Return the computed shared secret