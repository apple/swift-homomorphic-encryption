# ``HomomorphicEncryption``

Homomorphic Encryption (HE) enables computation on encrypted data.

## Overview
Swift Homomorphic Encryption is a collection of libraries and executables implementing homomorphic encryption (HE) and applications, such as private information retrieval (PIR).
For more information, refer to documentation for the libraries:
* [HomomorphicEncryptionProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/homomorphicencryptionprotobuf)
* [PrivateInformationRetrieval](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrieval)
* [PrivateInformationRetrievalProtobuf](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/privateinformationretrievalprotobuf)

and executables:
* [PIRGenerateDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirgeneratedatabase)
* [PIRProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirprocessdatabase)
* [PIRShardDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pirsharddatabase)

### Background
Swift Homomorphic Encryption implements a special form of cryptography called homomorphic encryption (HE).
HE is a cryptosystem which enables computation on encrypted data.
The computation is performed directly on the encrypted data, *without revealing the plaintext of that data to the operating process*.
HE computations therefore happen without decryption or access to the decryption key.

HE thereby allows a client to enable a server to perform operations on encrypted data, and therefore without revealing the data to server.
A typical HE workflow might be:
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
