# ``PrivateNearestNeighborSearch``

Private nearest neighbor search (PNNS) enables search on vector databases.

## Overview

Private nearest neighbor search (PNNS) enables a client with a private vector to search for the nearest vectors in a database hosted by a server, *without the server learning the client's vector.*.
Each row in the database is a *vector* with an associated *entry identifier* and *entry metadata*.
During the PNNS protocol, the client issues a query using its private vector, and learns the nearest neighbors according to a ``DistanceMetric``.
Specifically, the client learns the distances between the client's query vector to the nearest neighbors, as well as the entry identifier and entry metadata of the nearest neighbors.

A trivial implementation of PNNS is to have the client issue a generic "fetch database" request, independent of its private vector.
Then the server sends the entire database to the client, who computes the distances locally.
While this *trivial PNNS* protocol satisfies the privacy and correctness requirements of PNNS, it is only feasible for small databases.

The PNNS implementation in Swift Homomorphic Encryption uses homomorphic encryption to improve upon the trivial PNNS protocol.

See documentation for [PNNSGenerateDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pnnsgeneratedatabase) and  [PNNSProcessDatabase](https://swiftpackageindex.com/apple/swift-homomorphic-encryption/main/documentation/pnnsprocessdatabase) for more information.
