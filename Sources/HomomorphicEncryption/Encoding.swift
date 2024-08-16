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

// The encode/decode functions in context are not supposed to be called directly. Instead, one should call the
// corresponding encode/decode functions in specific Scheme instead.

extension Context {
    /// Encodes `values` in the given format.
    ///
    /// Encoding will use the top-level ciphertext context with all moduli.
    /// - Parameters:
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    /// - Returns: The plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    @inlinable
    public func encode(values: [some ScalarType], format: EncodeFormat) throws -> Plaintext<Scheme, Coeff> {
        try validDataForEncoding(values: values)
        switch format {
        case .coefficient:
            return try encodeCoefficient(values: values)
        case .simd:
            return try encodeSimd(values: values)
        }
    }

    /// Encodes `values` in the given format.
    /// - Parameters:
    ///   - values: Values to encode.
    ///   - format: Encoding format.
    ///   - moduliCount: Optional number of moduli. If not set, encoding will use the top-level ciphertext with all the
    /// moduli.
    /// - Returns: The plaintext encoding `values`.
    /// - Throws: Error upon failure to encode.
    @inlinable
    public func encode(
        values: [some ScalarType],
        format: EncodeFormat,
        moduliCount: Int? = nil) throws -> Plaintext<Scheme, Eval>
    {
        try Scheme.encode(context: self, values: values, format: format, moduliCount: moduliCount)
    }

    /// Decodes a plaintext with the given format.
    ///
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Format to decode with.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode.
    @inlinable
    public func decode<T: ScalarType>(plaintext: Plaintext<Scheme, Coeff>,
                                      format: EncodeFormat) throws -> [T]
    {
        switch format {
        case .coefficient:
            return decodeCoefficient(plaintext: plaintext)
        case .simd:
            return try decodeSimd(plaintext: plaintext)
        }
    }

    /// Decodes a plaintext with the given format.
    ///
    /// - Parameters:
    ///   - plaintext: Plaintext to decode.
    ///   - format: Format to decode with.
    /// - Returns: The decoded values.
    /// - Throws: Error upon failure to decode.
    @inlinable
    public func decode<T: ScalarType>(plaintext: Plaintext<Scheme, Eval>,
                                      format: EncodeFormat) throws -> [T]
    {
        try Scheme.decode(plaintext: plaintext, format: format)
    }

    @inlinable
    func validDataForEncoding(values: [some ScalarType]) throws {
        guard values.count <= encryptionParameters.polyDegree else {
            throw HeError.encodingDataCountExceedsLimit(count: values.count, limit: encryptionParameters.polyDegree)
        }
        for value in values {
            guard value < encryptionParameters.plaintextModulus else {
                throw HeError.encodingDataExceedsLimit(
                    limit: Int(encryptionParameters.plaintextModulus))
            }
        }
    }
}

// functions for coefficient encoding/decoding
extension Context {
    /// Encodes a polynomial element-wise in coefficient format.
    ///
    /// Encodes the polynomial
    /// `f(x) = values_0 + values_1 x + ... values_{N_1} x^{N-1}`, padding
    /// with 0 coefficients if fewer than `N` values are provided.
    @inlinable
    func encodeCoefficient(values: [some ScalarType]) throws
        -> Plaintext<Scheme, Coeff>
    {
        if values.isEmpty {
            return Plaintext<Scheme, Coeff>(context: self, poly: PolyRq.zero(context: plaintextContext))
        }
        let polyDegree = plaintextContext.degree
        var array: Array2d<Scheme.Scalar> = Array2d(array: Array2d(
            data: values,
            rowCount: 1,
            columnCount: values.count))
        array.resizeColumn(newColumnCount: polyDegree, defaultValue: Scheme.Scalar(0))
        return Plaintext<Scheme, Coeff>(
            context: self,
            poly: PolyRq(context: plaintextContext, data: array))
    }

    /// Decodes a polynomial element-wise in coefficient format.
    ///
    /// For plaintext polynomial `f(x) = \sum_{i=1}^{N-1} a_i x^i`,
    /// this function returns`[a_0, a_1, ..., a_{N-1}]`.
    /// - Parameter plaintext: Plaintext to decode.
    /// - Returns: The decoded plaintext values, each in `[0, t - 1]` for plaintext modulus `t`.
    @inlinable
    func decodeCoefficient<T: ScalarType>(plaintext: Plaintext<Scheme, Coeff>)
        -> [T]
    {
        Array2d(array: plaintext.poly.data).data
    }
}

// code for SIMD encoding/decoding
extension Context {
    @inlinable
    static func generateEncodingMatrix(encryptionParameters: EncryptionParameters<Scheme>) -> [Int] {
        guard encryptionParameters.plaintextModulus.isNttModulus(for: encryptionParameters.polyDegree) else {
            return [Int]()
        }

        let polyDegree = encryptionParameters.polyDegree
        let log2PolyDegree = polyDegree.log2
        let generator = Int(GaloisElementGenerator.value)
        let rowSize = (polyDegree >> 1)
        let twicePolyDegreeMask = (polyDegree << 1) - 1

        var indexMatrix = [Int](repeating: 0, count: polyDegree)
        var gPowerI = 1
        for i in 0..<rowSize {
            let index1 = (gPowerI - 1) >> 1
            let index2 = (twicePolyDegreeMask - gPowerI) >> 1
            indexMatrix[i] = Int(UInt32(index1).reverseBits(bitCount: log2PolyDegree))
            indexMatrix[rowSize | i] = Int(UInt32(index2).reverseBits(bitCount: log2PolyDegree))
            gPowerI *= generator
            gPowerI &= twicePolyDegreeMask
        }
        return indexMatrix
    }

    @inlinable
    func encodeSimd(values: [some ScalarType]) throws -> Plaintext<Scheme, Coeff> {
        guard !simdEncodingMatrix.isEmpty else { throw HeError.simdEncodingNotSupported(for: encryptionParameters) }
        let polyDegree = encryptionParameters.polyDegree
        var array = Array2d<Scheme.Scalar>.zero(rowCount: 1, columnCount: polyDegree)
        for index in 0..<values.count {
            array[0, simdEncodingMatrix[index]] = Scheme.Scalar(values[index])
        }
        let poly = PolyRq<_, Eval>(context: plaintextContext, data: array)
        let coeffPoly = try poly.inverseNtt()
        return Plaintext<Scheme, Coeff>(context: self, poly: coeffPoly)
    }

    @inlinable
    func decodeSimd<T: ScalarType>(plaintext: Plaintext<Scheme, Coeff>) throws -> [T] {
        guard !simdEncodingMatrix.isEmpty else {
            throw HeError.simdEncodingNotSupported(for: encryptionParameters)
        }
        let poly = try plaintext.poly.forwardNtt()
        return (0..<encryptionParameters.polyDegree).map { index in
            T(poly.data[0, simdEncodingMatrix[index]])
        }
    }
}
