# ``HomomorphicEncryption``

Homomorphic Encryption (HE) enables computation on encrypted data.

## Overview
Swift Homomorphic Encryption is a collection of libraries and executables implementing homomorphic encryption (HE) and applications, such as private information retrieval (PIR).
For more information, refer to documentation for the libraries:
* [HomomorphicEncryptionProtobuf](https://github.com/apple/swift-homomorphic-encryption/blob/main/Sources/HomomorphicEncryptionProtobuf/HomomorphicEncryptionProtobuf.docc/HomomorphicEncryptionProtobuf.md)
* [PrivateInformationRetrievalProtobuf](https://github.com/apple/swift-homomorphic-encryption/blob/main/Sources/PrivateInformationRetrievalProtobuf/PrivateInformationRetrievalProtobuf.docc/PrivateInformationRetrievalProtobuf.md)

and executables:
* [PIRGenerateDatabase](https://github.com/apple/swift-homomorphic-encryption/blob/main/Sources/PIRGenerateDatabase/PIRGenerateDatabase.docc/PIRGenerateDatabase.md)
* [PIRProcessDatabase](https://github.com/apple/swift-homomorphic-encryption/blob/main/Sources/PIRProcessDatabase/PIRProcessDatabase.docc/PIRProcessDatabase.md)
* [PIRShardDatabase](https://github.com/apple/swift-homomorphic-encryption/blob/main/Sources/PIRShardDatabase/PIRShardDatabase.docc/PIRShardDatabase.md)

### Background
Homomorphic encryption (HE) is a cryptosystem which enables computation on encrypted data.
The computation is performed directly on the encrypted data, without decryption or use of a secret key.
HE thereby enables a client to offload computation on its sensitive data to a server by the following workflow:
* The client encrypts its sensitive data and sends the resulting ciphertext to the server.
* The server performs HE computation on the ciphertext (and perhaps its own plaintext inputs), without learning what any ciphertext decrypts to.
* The server sends the resulting ciphertext response to the client.
* The client decrypts to learn the response.

Swift Homomorphic Encryption implements the Brakerski-Fan-Vercauteren (BFV) HE scheme, which is based on the ring learning with errors (RLWE) hardness problem.
This scheme can be configured to support post-quantum 128-bit security.

> Warning: BFV does not provide IND-CCA security, and should be used accordingly.
> In particular, as little information as possible about each decrypted ciphertext should be sent back to the server. To protect against a malicious server, the client should also validate the decrypted content is in the expected format.
>
> Consult a cryptography expert when developing and deploying homomorphic encryption applications.