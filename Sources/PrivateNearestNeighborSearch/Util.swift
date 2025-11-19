// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import Algorithms
public import Foundation
public import HomomorphicEncryption
public import ModularArithmetic

extension Array2d where T == Float {
    /// A mapping from vectors to non-negative real numbers.
    @usableFromInline
    package enum Norm: Equatable {
        case Lp(p: Float) // sum_i (|x_i|^p)^{1/p}
    }

    /// Normalizes each row in the matrix.
    @inlinable
    package func normalizedRows(norm: Norm) -> Array2d<Float> {
        switch norm {
        case let Norm.Lp(p):
            let normalizedValues = data.chunks(ofCount: columnCount).flatMap { row in
                let sumOfPowers = row.map { pow($0, p) }.reduce(0, +)
                let norm = pow(sumOfPowers, 1 / p)
                return row.map { value in
                    if sumOfPowers.isZero {
                        Float.zero
                    } else {
                        value / norm
                    }
                }
            }
            return Array2d<Float>(
                data: normalizedValues,
                rowCount: rowCount,
                columnCount: columnCount)
        }
    }

    /// Returns the matrix where each entry is rounded to the closest integer.
    @inlinable
    package func rounded<V: FixedWidthInteger & SignedInteger>() -> Array2d<V> {
        Array2d<V>(
            data: data.map { value in V(value.rounded()) },
            rowCount: rowCount,
            columnCount: columnCount)
    }

    /// Returns the matrix where each entry has been multiplied by a scaling factor.
    /// - Parameter scalingFactor: The factor to multiply each entry by.
    /// - Returns: The scaled matrix.
    @inlinable
    package func scaled(by scalingFactor: Float) -> Array2d<Float> {
        Array2d<Float>(
            data: data.map { value in value * scalingFactor },
            rowCount: rowCount,
            columnCount: columnCount)
    }

    /// Normalizes the each rows' vector with L2 norm, then scales and rounds each entry.
    /// - Parameter scalingFactor: The factor to multiply each entry by.
    /// - Returns: The matrix after the normalization, scaling, and rounding.
    @inlinable
    package func normalizedScaledAndRounded<V: FixedWidthInteger & SignedInteger>(scalingFactor: Float) -> Array2d<V> {
        let normalizedValues = data.chunks(ofCount: columnCount).flatMap { row in
            let norm = row.map { $0 * $0 }.reduce(0, +).squareRoot()
            return row.map { value in
                if norm.isZero {
                    V.zero
                } else {
                    V((value * scalingFactor / norm).rounded())
                }
            }
        }
        return Array2d<V>(
            data: normalizedValues,
            rowCount: rowCount,
            columnCount: columnCount)
    }
}

extension Array2d where T: SignedScalarType {
    /// Performs modular matrix multiplication.
    /// - Parameters:
    ///   - rhs: Matrix to multiply with.
    ///   - modulus: Modulus.
    /// - Returns: The matrix product; each value is in `[-floor(modulus/2), floor(modulus-1)/2]`
    @inlinable
    package func mul(_ rhs: Self, modulus: T.UnsignedScalar) -> Self {
        precondition(columnCount == rhs.rowCount)
        let signedModulus = T(modulus)
        var result = Array2d.zero(rowCount: rowCount, columnCount: rhs.columnCount)
        for row in 0..<rowCount {
            for column in 0..<rhs.columnCount {
                for innerDimension in 0..<columnCount {
                    var product = self[row, innerDimension].multiplyMod(
                        rhs[innerDimension, column],
                        modulus: signedModulus,
                        variableTime: true)
                    if product < 0 {
                        product += signedModulus
                    }
                    var sum = result[row, column] + product
                    if sum >= signedModulus {
                        sum -= signedModulus
                    }
                    result[row, column] = sum
                }
                result[row, column] = T.UnsignedScalar(result[row, column]).remainderToCentered(modulus: modulus)
            }
        }
        return result
    }
}

extension Array2d where T == Float {
    @inlinable
    package func mul(_ rhs: Self) -> Self {
        precondition(columnCount == rhs.rowCount)
        var result = Array2d.zero(rowCount: rowCount, columnCount: rhs.columnCount)
        for row in 0..<rowCount {
            for column in 0..<rhs.columnCount {
                for innerDimension in 0..<columnCount {
                    result[row, column] += self[row, innerDimension] * rhs[innerDimension, column]
                }
            }
        }
        return result
    }

    @inlinable
    package func fixedPointCosineSimilarity<V: ScalarType>(_ rhs: Self, modulus: V,
                                                           scalingFactor: Float) throws -> Self
    {
        let lhsScaled: Array2d<V.SignedScalar> = normalizedScaledAndRounded(scalingFactor: scalingFactor)
        let rhsScaled: Array2d<V.SignedScalar> = rhs.transposed()
            .normalizedScaledAndRounded(scalingFactor: scalingFactor)
            .transposed()
        let product = lhsScaled.mul(rhsScaled, modulus: modulus)
        return product.map { Float($0) / (scalingFactor * scalingFactor) }
    }
}

@inlinable
package func fixedPointCosineSimilarityError(innerDimension _: Int, scalingFactor: Int) -> Float {
    // With scaling factor 10, 0.45 would round to 0.50, for error 0.05
    let scaleAndRoundError = 1.0 / Float(2 * scalingFactor)
    return pow(1 + scaleAndRoundError, 2) - 1.0
}
