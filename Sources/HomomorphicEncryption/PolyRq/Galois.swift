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
    /// Applies a Galois transformation, also known as a Frobenius transformation.
    ///
    /// The Galois transformation with Galois element `p` transforms the polynomial `f(x)` to `f(x^p)`.
    /// - Parameter element: Galois element of the transformation.
    /// - Returns: The polynomial after applying the Galois transformation.
    @inlinable
    public func applyGalois(element: Int) -> Self {
        precondition(element.isValidGaloisElement(for: degree))
        var output = self
        for (rnsIndex, modulus) in moduli.enumerated() {
            var iterator = GaloisCoeffIterator(degree: degree, galoisElement: element)
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
    /// Applies a Galois transformation, also known as a Frobenius transformation.
    ///
    /// The Galois transformation with Galois element `p` transforms the polynomial `f(x)` to `f(x^p)`.
    /// - Parameter element: Galois element of the transformation.
    /// - Returns: The polynomial after applying the Galois transformation.
    /// - Throws: Error upon failure to perform the transoromation.
    @inlinable
    public func applyGalois(element: Int) throws -> Self {
        precondition(element.isValidGaloisElement(for: degree))
        var output = self

        var iterator = GaloisEvalIterator(degree: degree, galoisElement: element)
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

    /// Returns all Galois elements up to logarithm of `degree / 2`.
    ///
    /// - Parameter degree: The is the RLWE ring dimension `N`, given by
    /// ``EncryptionParameters/polyDegree``.
    /// - Returns: Array of Galois elements.
    /// - Throws: Error upon invalid step or degree.
    @inlinable
    package static func rotatingColumnsMultiStep(degree: Int) throws -> [Int] {
        var elements: [Int] = []
        for logStep in 0..<(degree / 2).log2 {
            let step = 1 << logStep
            try elements.append(rotatingColumns(by: step, degree: degree))
            try elements.append(rotatingColumns(by: -step, degree: degree))
        }
        return elements
    }

    /// Computes rotation steps corresponding to Galois elements.
    ///
    /// - Parameters:
    ///   - elements: Galois elements.
    ///   - degree: The RLWE ring dimension `N`, given by
    /// ``EncryptionParameters/polyDegree``.
    /// - Returns: Dictionary mapping Galois elements to their corresponding rotation steps.
    @inlinable
    package static func stepsFor(elements: [Int], degree: Int) -> [Int: Int?] {
        var result: [Int: Int?] = Dictionary(elements.map { ($0, nil) }) { first, _ in
            first
        }

        let modulus = 2 * degree
        var resultCount = 0
        var gPowStep = 1
        for step in 0...(degree / 2) {
            if elements.contains(gPowStep) {
                result[gPowStep] = degree / 2 - step
                resultCount += 1
                if resultCount == elements.count {
                    return result
                }
            }
            gPowStep = gPowStep.multiplyMod(Int(GaloisElementGenerator.value), modulus: modulus, variableTime: true)
        }
        return result
    }

    /// Decomposes `step` into smaller rotation steps and associated number of repetitions.
    ///
    /// When the smaller rotation steps are applied with specified repetitions, the result is rotation by `step`.
    /// - Parameters:
    ///   - supportedSteps: Smaller rotation steps to decompose into.
    ///   - step: Number of slots to rotate. Negative values indicate a left rotation, and positive values indicate
    /// right rotation.
    ///   - degree: This is the RLWE ring dimension `N`, given by
    /// ``EncryptionParameters/polyDegree``.
    /// - Returns: Dictionary mapping rotation steps to their counts, and `nil` if no plan was found.
    /// - Throws: Error upon invalid step or degree.
    @inlinable
    package static func planMultiStep(supportedSteps: [Int], step: Int, degree: Int) throws -> [Int: Int]? {
        guard abs(step) < degree else {
            throw HeError.invalidRotationStep(step: step, degree: degree)
        }
        if supportedSteps.contains(step) {
            return [step: 1]
        }

        let sortedSteps = supportedSteps.sorted(by: >)
        let positiveStepsPlan = planMultiStepGreedy(sortedSteps: sortedSteps, step: step) { $0 }
        let negativeStepsPlan = planMultiStepGreedy(sortedSteps: sortedSteps.reversed(), step: step) { step in
            let columnsCount = degree >> 1
            return columnsCount - step
        }

        return switch (positiveStepsPlan, negativeStepsPlan) {
        case (nil, nil):
            nil
        case let (nil, negativePlan?):
            negativePlan
        case let (positivePlan?, nil):
            positivePlan
        case let (positivePlan?, negativePlan?):
            if positivePlan.values.reduce(0, +) <= negativePlan.values.reduce(0, +) {
                positivePlan
            } else {
                negativePlan
            }
        }
    }

    @inlinable
    static func planMultiStepGreedy(sortedSteps: [Int], step: Int, stepTransform: (Int) -> Int) -> [Int: Int]? {
        var resultSteps: [Int: Int] = [:]
        var remainingStep = stepTransform(step)
        for supportedStep in sortedSteps {
            let transformedStep = stepTransform(supportedStep)
            let stepCount = remainingStep / transformedStep
            if stepCount > 0 {
                resultSteps[supportedStep] = (resultSteps[supportedStep] ?? 0) + stepCount
            }
            remainingStep %= transformedStep
        }
        if remainingStep == 0 {
            return resultSteps
        }
        return nil
    }
}
