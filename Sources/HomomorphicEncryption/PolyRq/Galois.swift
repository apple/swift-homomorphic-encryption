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

@usableFromInline
struct GaloisCoeffIterator: IteratorProtocol {
    @usableFromInline typealias Element = (Bool, Int)

    /// Degree of the RLWE polynomial.
    @usableFromInline let degree: Int
    /// `log2(degree)`.
    @usableFromInline let log2Degree: Int
    /// `x % degree == x & modDegreeMask`, because `degree` is a power of two.
    @usableFromInline let modDegreeMask: Int
    /// power in transformation `f(x) -> f(x^{galoisElement})`.
    @usableFromInline let galoisElement: Int
    /// simple incrementing index of the iterator in `[0, degree)`.
    @usableFromInline var iterIndex: Int
    /// `iterIndex * galoisElement`.
    @usableFromInline var rawOutIndex: Int
    /// Raw output index mod-reduced to `[0, degree)`.
    @usableFromInline var outIndex: Int

    @inlinable
    init(degree: Int, galoisElement: Int) {
        precondition(galoisElement.isValidGaloisElement(for: degree))
        self.degree = degree
        self.log2Degree = degree.log2
        self.modDegreeMask = degree &- 1
        self.galoisElement = galoisElement
        self.iterIndex = 0
        self.rawOutIndex = 0
        self.outIndex = 0
    }

    @inlinable
    mutating func next() -> Element? {
        if iterIndex < degree {
            // Use x^degree == -1 mod (x^degree + 1)
            // floor(outRawIdx / degree) odd => negate coefficient
            let negate = (rawOutIndex >> log2Degree) & 1 != 0
            let ret = (negate, Int(outIndex))
            iterIndex &+= 1
            rawOutIndex &+= galoisElement
            outIndex = rawOutIndex & modDegreeMask
            return ret
        }
        return nil
    }
}

@usableFromInline
struct GaloisEvalIterator: IteratorProtocol {
    @usableFromInline typealias Element = Int
    /// Degree of the RLWE polynomial.
    @usableFromInline let degree: Int
    /// `log2(degree)`.
    @usableFromInline let log2Degree: Int
    /// `x % degree == x & modDegreeMask`, because `degree` is a power of two.
    @usableFromInline let modDegreeMask: Int
    /// Power in transformation `f(x) -> f(x^{galoisElement})`.
    @usableFromInline let galoisElement: Int
    /// Simple incrementing index of the iterator in `[0, degree)`.
    @usableFromInline var iterIndex: Int

    @inlinable
    init(degree: Int, galoisElement: Int) {
        precondition(galoisElement.isValidGaloisElement(for: degree))
        self.degree = degree
        self.log2Degree = degree.log2
        self.modDegreeMask = degree &- 1
        self.galoisElement = galoisElement
        self.iterIndex = 0
    }

    @inlinable
    mutating func next() -> Element? {
        if iterIndex < degree {
            let reversed = Int(UInt32(iterIndex &+ degree).reverseBits(bitCount: log2Degree &+ 1))
            var indexRaw = (galoisElement &* reversed) &>> 1
            indexRaw &= modDegreeMask
            iterIndex &+= 1
            return Int(UInt32(indexRaw).reverseBits(bitCount: log2Degree))
        }
        return nil
    }
}

extension FixedWidthInteger {
    @inlinable
    func isValidGaloisElement(for degree: Int) -> Bool {
        degree.isPowerOfTwo && !isMultiple(of: 2) && (self < (degree &<< 1)) && (self > 1)
    }
}

extension PolyRq where F == Coeff {
    @inlinable
    public func applyGalois(galoisElement: Int) -> Self {
        precondition(galoisElement.isValidGaloisElement(for: degree))
        var output = self
        for (rnsIndex, modulus) in moduli.enumerated() {
            var iterator = GaloisCoeffIterator(degree: degree, galoisElement: galoisElement)
            let dataIndices = data.rowIndices(row: rnsIndex)
            func outputIndex(column: Int) -> Int {
                data.index(row: rnsIndex, column: column)
            }
            data.data.withUnsafeBufferPointer { dataPtr in
                output.data.data.withUnsafeMutableBufferPointer { outputPtr in
                    for dataIndex in dataIndices {
                        guard let (negate, outIndex) = iterator.next() else {
                            preconditionFailure("GaloisCoeffIterator goes out of index")
                        }
                        if negate {
                            outputPtr[outputIndex(column: outIndex)] = dataPtr[dataIndex]
                                .negateMod(modulus: modulus)
                        } else {
                            outputPtr[outputIndex(column: outIndex)] = dataPtr[dataIndex]
                        }
                    }
                }
            }
        }

        return output
    }
}

extension PolyRq where F == Eval {
    @inlinable
    public func applyGalois(galoisElement: Int) throws -> Self {
        precondition(galoisElement.isValidGaloisElement(for: degree))
        var output = self

        var iterator = GaloisEvalIterator(degree: degree, galoisElement: galoisElement)
        for dataIndex in coeffIndices {
            guard let inIndex = iterator.next() else {
                preconditionFailure("GaloisEvalIterator goes out of index")
            }
            for modulusIndex in moduli.indices {
                output.data[modulusIndex, dataIndex] = data[modulusIndex, inIndex]
            }
        }
        return output
    }
}

@usableFromInline
enum GaloisElementGenerator {
    @usableFromInline static let value: UInt32 = 3
}

/// Utilities for generating Galois elements.
public enum GaloisElement {
    /// Returns the Galois element to swap rows.
    ///
    /// - Parameter degree: Polynomial degree.
    /// - Returns: The Galois element to swap rows.
    /// - seealso: ``HeScheme/swapRows(of:using:)`` for more information.
    @inlinable
    public static func swappingRows(degree: Int) -> Int {
        (degree << 1) - 1
    }

    /// Returns the Galois element for column rotation by `step`.
    ///
    /// - Parameters:
    ///   - step: Number of slots to rotate. Negative values indicate a left rotation, and positive values indicate
    /// right rotation. Must have absolute value in `[1, N / 2 - 1]`
    ///   - degree: The is the RLWE ring dimension `N`, given by
    /// ``EncryptionParameters/polyDegree``.
    /// - Returns: The Galois element for column rotation by `step`.
    /// - Throws: Error upon invalid step or degree.
    @inlinable
    public static func rotatingColumns(by step: Int, degree: Int) throws -> Int {
        guard degree.isPowerOfTwo else {
            throw HeError.invalidDegree(degree)
        }
        var positiveStep = UInt32(abs(step))
        guard positiveStep < (degree &>> 1), positiveStep > 0 else {
            throw HeError.invalidRotationStep(step: step, degree: degree)
        }
        let twiceDegreeMinus1 = (degree &<< 1) &- 1
        positiveStep &= UInt32(twiceDegreeMinus1)
        if step > 0 {
            positiveStep = UInt32(degree &>> 1) &- positiveStep
        }
        return Int(GaloisElementGenerator.value.powMod(
            exponent: positiveStep,
            modulus: UInt32(degree) &<< 1,
            variableTime: true))
    }
}
