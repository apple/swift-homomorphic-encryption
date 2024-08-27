# ``PrivateInformationRetrieval``

Private information retrieval (PIR) enables private database lookup.

## Overview

Private information retrieval (PIR) allows a client to perform a database lookup from a server hosting a keyword-value database, *without the server learning the keyword in the client's query.*.
Each row in the database is a *keyword* with an associated *value*.
During the PIR protocol, the client issues a query using its private keyword, and learns the value associated with the keyword.

A trivial implementation of PIR is to have the client issue a generic "fetch database" request, independent of its private keyword.
Then the server server sends the entire database to the client.
While this *trivial PIR* protocol satisfies the privacy and correctness requirements of PIR, it is only feasible for small databases.

The PIR implementation in Swift Homomorphic Encryption uses homomorphic encryption to improve upon the trivial PIR protocol.

> Warning: PIR is asymmetric, meaning the client may learn keyword-value pairs not requested, as happens in trivial PIR for instance.
> A variant of PIR, known as *symmetric PIR*, would be required to ensure the client does not learn anything about values it did not request.

## Topics
<!-- Snippets are defined in a different "virtual module", requiring manually linking articles here. -->
### Articles
- <doc:EncodingPipeline>
- <doc:ParameterTuning>
- <doc:ReusingPirParameters>
