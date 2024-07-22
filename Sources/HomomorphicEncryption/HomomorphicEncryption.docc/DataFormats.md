# Data Formats

Representation and serialization of polynomials and related objects.

## Overview

Objects containing polynomials have multiple distinct representations. For instance, the structures ``Plaintext`` and ``SerializedPlaintext``, and the protobuf message `SerializedPlaintext` all represent plaintexts in different contexts. Same for ciphertexts and keys.

The structures ``Plaintext``, ``Ciphertext``, ``SecretKey``, etc. are used at run-time to carry out computations. In addition to data, these structures have references to "contexts" (see below) that facilitate these computations. Serialization structures like ``SerializedPlaintext``, ``SerializedCiphertext``, ``SerializedSecretKey``, etc. serialize the run-time structures' data (not the context) into a byte array which serves as an intermediate serialization format, independent of the wire protocol. The protobuf objects like ``SerializedPlaintext`` implement the particular wire protocol.

Plaintexts, ciphertexts, and keys need a serialization protocol, as they are stored on disk during processing, and sent over the wire. The crux of serializing these objects is serializing the polynomials they contain, so let's look at polynomial representation and serialization.

### Polynomial Representation

The ``PolyRq`` struct represents a polynomial in `R_q = Z_q[X] / (X^N + 1)`, that is, degree `N` polynomials where each coefficient is an integer mod `q`. The polynomial is represented either as coefficients (``Coeff``) or as evaluations (``Eval``), called terms. Each of these individual terms (i.e., a coefficient or an evaluation) is represented as residues relative to a given list of moduli.

During an execution, many polynomials contained in plaintexts, ciphertexts and keys share a lot of information. These polynomials have distinct coefficients, but they can have the same degree, moduli basis, etc. There are also common parameters used during computation. From a serialization perspective, it is wasteful to serialize this information for all polynomials, so redundant elements are separated out into a `context` as described next.

Inside `PolyRq`, the polynomial coefficients themselves are stored in an ``Array2d`` named `data`, where columns correspond to the coefficient index, and rows correspond to RNS moduli. The number of columns is equal to the degree of the polynomial. Thus, entry `(i,j)` is the residue of the `j`th coefficient relative to the `i`th modulus. The moduli and other information about the polynomial (including its degree) are stored in a ``PolyContext`` named `context`.

To serialize a polynomial, only the coefficients are serialized, and not the `context`. (This implies that during deserialization, we need to pass a `context` with correct list of moduli.)

The ``Plaintext`` struct contains a ``PolyRq`` polynomial, which in turn contains the `context`. The ``SerializedPlaintext`` struct contains the serialization of the _coefficients_ of the polynomial as an array of bytes. Details of this serialization are describe in the section below. The protobuf message ``SerializedPlaintext`` is the protobuf serialization of ``SerializedPlaintext`` used as the wire protocol. Thus,``SerializedPlaintext`` is an intermediate serialization that makes it easy to change the wire protocol without changing low-level polynomial representation.

Similar discussion applies to keys and ciphertexts.

### Serializing Polynomials

Coefficients in `data` are serialized in a row-major manner. Residues for all coefficients relative to the first modulus are serialized first, then all residues relative to the second modulus, and so on.

For a specific modulus, serialization packs the residues in an array of bytes. Each residue can be represented in `ceil(log(modulus)` bits, and thus the entire row requires `degree * ceil(log(modulus))`  bits. The array of bytes is considered a contiguous sequence of bits, and the residues are packed in order, in fixed-width chunks of `ceil(log(modulus))`  bits each. If the total number of bits is not divisible by 8, then the remaining bits in the last byte are set to 0.

For decryption, some number of least significant bits of the coefficients can be ignored without affecting the result. Thus, we can ignore those bits from the serialization too, resulting in smaller message size. For ciphertexts meant for decryption only, calling ``Ciphertext/serialize(forDecryption:)`` with `forDecryption: true` will calculate the number of bits to skip and serialize appropriately.

Similar packing is done for all moduli. The final output is the single array obtained by concatenating the serializations of residues for each modulus as it appears in ``PolyContext``.
