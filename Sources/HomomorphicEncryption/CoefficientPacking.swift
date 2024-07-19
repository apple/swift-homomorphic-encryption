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

/// Utilities to transcode between bytes and scalar coefficients.
public enum CoefficientPacking {}

extension CoefficientPacking {
    @inlinable
    static func bytesToCoefficientsCoeffCount(byteCount: Int, bitsPerCoeff: Int, decode: Bool,
                                              skipLSBs: Int = 0) -> Int
    {
        let bitsPerByte = UInt8.bitWidth
        let serializedBitsPerCoeff = bitsPerCoeff - skipLSBs
        if decode {
            return bitsPerByte * byteCount / serializedBitsPerCoeff
        }
        return (bitsPerByte * byteCount).dividingCeil(serializedBitsPerCoeff, variableTime: true)
    }

    /// Converts a sequence of bytes to a vector of fixed bit-width coefficients.
    /// - Parameters:
    ///   - bytes: Serialized coefficients.
    ///   - bitsPerCoeff: Number of bits in each coefficient.
    ///   - decode: If `true`, then it is assumed that `bytes` is a a sequence of serialized coefficients and we are
    /// transforming these back to coefficients. In that case, the coefficient bit-size and byte bit-size might not
    /// match up, which would mean that the last byte will only contain partial information, and we do not need an extra
    /// coefficient to store the remaining bits of the last byte.
    ///   - skipLSBs: How many least-significant bits from each coefficient are assumed to be 0, and not present in
    /// `bytes`.
    /// - Returns: The deserialized coefficients.
    /// - seealso: ``CoefficientPacking/coefficientsToBytes(coeffs:bitsPerCoeff:skipLSBs:)``
    @inlinable
    public static func bytesToCoefficients<T: ScalarType>(bytes: [UInt8], bitsPerCoeff: Int, decode: Bool,
                                                          skipLSBs: Int = 0) -> [T]
    {
        var coeffs: [T] = .init(
            repeating: 0,
            count: bytesToCoefficientsCoeffCount(
                byteCount: bytes.count,
                bitsPerCoeff: bitsPerCoeff,
                decode: decode,
                skipLSBs: skipLSBs))
        bytesToCoefficientsInplace(bytes: bytes, coeffs: &coeffs, bitsPerCoeff: bitsPerCoeff, skipLSBs: skipLSBs)
        return coeffs
    }

    ///  Converts an sequence of bytes into coefficients, unused bits in the last coefficient will be set to zero.
    @inlinable
    static func bytesToCoefficientsInplace<T, C>(
        bytes: some Sequence<UInt8>,
        coeffs: inout C,
        bitsPerCoeff: Int,
        skipLSBs: Int = 0)
        where T: ScalarType,
        C: MutableCollection,
        C.Element == T,
        C.Index == Int
    {
        precondition(bitsPerCoeff > 0)
        precondition(bitsPerCoeff > skipLSBs)

        let serializedBitCount = bitsPerCoeff - skipLSBs
        var coeffIndex = coeffs.startIndex
        var coeff: T = 0
        var remainingCoeffBits = serializedBitCount

        // consume bytes and populate coefficients
        for byte in bytes {
            var remainingBits = UInt8.bitWidth
            var byte = byte
            repeat {
                let shift = min(remainingBits, remainingCoeffBits)
                coeff &<<= shift
                coeff |= T(byte &>> (UInt8.bitWidth - shift))
                byte = byte &<< shift
                remainingCoeffBits &-= shift
                remainingBits &-= shift

                if remainingCoeffBits == 0 {
                    remainingCoeffBits = serializedBitCount
                    coeffs[coeffIndex] = coeff &<< skipLSBs
                    coeffIndex &+= 1
                    coeff = 0
                }
            } while remainingBits > 0
        }
        if coeffIndex < coeffs.endIndex {
            coeff &<<= (remainingCoeffBits &+ skipLSBs)
            coeffs[coeffIndex] = coeff
            coeffIndex &+= 1
        }
        precondition(coeffIndex == coeffs.endIndex)
    }

    @inlinable
    package static func coefficientsToBytesByteCount(coeffCount: Int, bitsPerCoeff: Int, skipLSBs: Int = 0) -> Int {
        let serializedBitsPerCoeff = bitsPerCoeff - skipLSBs
        return (coeffCount * serializedBitsPerCoeff).dividingCeil(UInt8.bitWidth, variableTime: true)
    }

    /// Converts a sequence of fixed bit-width coefficients to bytes.
    /// - Parameters:
    ///   - coeffs: Coefficients
    ///   - bitsPerCoeff: Number of bits in each coefficient.
    ///   - skipLSBs: How many least-significant bits from each coefficient to omit from serialization.
    /// - Returns: The serialized coefficients.
    /// - Throws: Error upon failure to convert the coefficients.
    /// - seealso ``CoefficientPacking/bytesToCoefficients(bytes:bitsPerCoeff:decode:skipLSBs:)``.
    @inlinable
    public static func coefficientsToBytes(coeffs: [some ScalarType], bitsPerCoeff: Int,
                                           skipLSBs: Int = 0) throws -> [UInt8]
    {
        var bytes: [UInt8] = .init(
            repeating: 0,
            count: coefficientsToBytesByteCount(
                coeffCount: coeffs.count,
                bitsPerCoeff: bitsPerCoeff,
                skipLSBs: skipLSBs))
        try coefficientsToBytesInplace(coeffs: coeffs, bytes: &bytes, bitsPerCoeff: bitsPerCoeff, skipLSBs: skipLSBs)
        return bytes
    }

    @inlinable
    static func coefficientsToBytesInplace<T, C>(
        coeffs: some Sequence<T>,
        bytes: inout C,
        bitsPerCoeff: Int,
        skipLSBs: Int = 0) throws
        where T: ScalarType,
        C: MutableCollection,
        C.Element == UInt8,
        C.Index == Int
    {
        precondition(bitsPerCoeff > 0)
        precondition(bitsPerCoeff > skipLSBs)

        var byteIndex = 0
        let bytesCount = bytes.count
        let serializedBitCount = bitsPerCoeff - skipLSBs
        guard bytes.withContiguousMutableStorageIfAvailable({ bytesPtr in
            var byte: UInt8 = 0
            var remainingBits = UInt8.bitWidth

            // consume coefficients and populate bytes
            for coeff in coeffs {
                let coeff = coeff &>> skipLSBs
                var remainingCoeffBits = serializedBitCount
                repeat {
                    if remainingBits == 0 {
                        remainingBits = UInt8.bitWidth
                        bytesPtr[byteIndex] = byte
                        byteIndex &+= 1
                        if byteIndex == bytesCount {
                            return
                        }
                        byte = 0
                    }

                    let shift = min(remainingBits, remainingCoeffBits)
                    let byteValue = UInt8(coeff &>> (remainingCoeffBits &- shift) & T(UInt8.max))
                    byte = byte &<< shift | byteValue
                    remainingCoeffBits &-= shift
                    remainingBits &-= shift
                } while remainingCoeffBits > 0
            }

            if byteIndex < bytesCount {
                byte &<<= remainingBits
                bytesPtr[byteIndex] = byte
                byteIndex &+= 1
            }
            precondition(byteIndex == bytesCount)
        }) != nil else {
            throw HeError.serializationBufferNotContiguous
        }
    }
}
