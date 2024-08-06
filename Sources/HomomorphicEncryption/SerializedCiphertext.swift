// Copyright 2024 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Serialized ciphertext object.
///
/// It can be one of the two cases:
/// * seeded - the tuple contains the serialization of the first polynomial and the seed for generating the second
/// polynomial.
/// * full - we have one data element that contains the full serialization of all the polynomials in the ciphertext.
public enum SerializedCiphertext<Scalar: ScalarType>: Hashable, Codable, Sendable {
    /// Full ciphertext.
    /// - Parameters:
    ///   - polys: serialization of all the polynomials in the ciphertext.
    ///   - skipLsbs: i'th polynomial's coefficients omit serialization of the `skipLsbs[i]` least significant bits.
    ///   - correctionFactor: the correction factor for the ciphertext.
    case full(polys: [UInt8], skipLSBs: [Int], correctionFactor: Scalar)
    /// Seeded ciphertext.
    /// - Parameters:
    ///   - poly0: serialization of the first polynomial.
    ///   - seed: seed to generate the second polynomial.
    case seeded(poly0: [UInt8], seed: [UInt8])
}

extension Ciphertext {
    /// Deserializes a serialized ciphertext.
    /// - Parameters:
    ///   - serialized: Serialized ciphertext.
    ///   - context: Context to associate with the ciphertext.
    ///   - moduliCount: Number of moduli in the serialized ciphertext.
    /// - Throws: Error upon failure to deserialize the ciphertext.
    @inlinable
    public init(
        deserialize serialized: SerializedCiphertext<Scalar>,
        context: Context<Scheme>,
        moduliCount: Int? = nil) throws
    {
        self.context = context
        let moduliCount = moduliCount ?? context.ciphertextContext.moduli.count
        let polyContext = try context.secretKeyContext.getContext(moduliCount: moduliCount)
        switch serialized {
        case let .seeded(poly0: poly0, seed: seed):
            let poly = try PolyRq<_, Format>(deserialize: poly0, context: polyContext)
            var rng = try NistAes128Ctr(seed: seed)
            let a = PolyRq<_, Eval>.random(context: polyContext, using: &rng)
            let poly1: PolyRq<Scalar, Format> = try a.convertFormat()
            self.polys = [poly, poly1]
            self.correctionFactor = 1
            self.seed = seed
        case let .full(polys: polys, skipLSBs: skipLSBs, correctionFactor: correctionFactor):
            self.polys = try Serialize.deserializePolys(from: polys, context: polyContext, skipLSBs: skipLSBs)
            self.correctionFactor = correctionFactor
        }
    }

    /// Serializes a ciphertext, retaining decryption correctness only at the given indices.
    ///
    /// When only a few indices are known to contain meaningful information, this can yield a serialized ciphertext
    /// which is more compressible than a typical serialized ciphertext.
    /// - Parameters:
    ///   - coeffIndices: The coefficient indices for which to preserve correctness of decryption. If specified, must
    /// the ciphertext must be in ``Coeff`` format.
    ///   - forDecryption: If true, serialization may use a more concise format, yielding a ciphertext which,
    /// once deserialized, is only compatible with decryption, and not any other HE operations.
    /// - Returns: The serialized ciphertext.
    /// - Throws: Error upon failure to serialize.
    @inlinable
    public func serialize(indices coeffIndices: [Int]? = nil,
                          forDecryption: Bool = false) throws -> SerializedCiphertext<Scalar>
    {
        var toSerialize = self
        if let coeffIndices {
            guard Format.self == Coeff.self else {
                throw HeError.invalidFormat(Format.self)
            }
            var poly0 = PolyRq<Scheme.Scalar, Format>.zero(context: polyContext())
            for coeffIndex in coeffIndices {
                guard poly0.coeffIndices.contains(coeffIndex) else {
                    throw HeError.invalidCoefficientIndex(
                        index: coeffIndex,
                        degree: poly0.degree)
                }
            }
            for rnsIndex in poly0.rnsIndices {
                for coeffIndex in coeffIndices {
                    let index = poly0.index(rnsIndex: rnsIndex, coeffIndex: coeffIndex)
                    poly0[index] = polys[0][index]
                }
            }
            toSerialize.polys[0] = poly0
        }
        return toSerialize.serialize(forDecryption: forDecryption)
    }

    /// Serializes a ciphertext.
    /// - Parameter forDecryption: If true, serialization may use a more concise format, yielding a ciphertext which,
    /// once deserialized, is only compatible with decryption, and not any other HE operations.
    /// - Returns: The serialized ciphertext.
    /// - seealso: ``Ciphertext/serialize(indices:forDecryption:)``.
    @inlinable
    func serialize(forDecryption: Bool = false) -> SerializedCiphertext<Scalar> {
        if !seed.isEmpty, polys.count == 2 {
            return serialize(seed: seed)
        }

        let skipLSBs: [Int] = if forDecryption, polyContext().moduli.count == 1,
                                 polys.count == context.encryptionParameters
                                 .skipLSBsForDecryption().count
        {
            context.encryptionParameters.skipLSBsForDecryption()
        } else {
            Array(repeating: 0, count: polys.count)
        }

        var byteCount = MemoryLayout<UInt16>.size
        for skipLSB in skipLSBs {
            byteCount += polyContext().serializationByteCount(skipLSBs: skipLSB)
        }
        var polysBuffer = [UInt8](repeating: 0, count: byteCount)
        // safe because we initialize the buffer with correct count
        // swiftlint:disable:next force_try
        try! Serialize
            .serializePolys(
                polys,
                to: &polysBuffer,
                context: polyContext(),
                skipLSBs: skipLSBs)
        return .full(
            polys: polysBuffer,
            skipLSBs: skipLSBs,
            correctionFactor: correctionFactor)
    }

    @inlinable
    func serialize(seed: [UInt8]) -> SerializedCiphertext<Scalar> {
        precondition(polys.count == 2)
        let polyBuffer = polys[0].serialize()
        return .seeded(poly0: polyBuffer, seed: seed)
    }
}
