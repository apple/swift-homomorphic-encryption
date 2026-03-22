// Copyright 2025-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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

public import HomomorphicEncryption

/// Pre-computed encoding map for fast PlaintextMatrix construction.
///
/// When the database dimensions, packing, and encryption parameters are fixed,
/// the mapping from input vector values to SIMD slot positions is deterministic.
/// This struct caches that mapping so subsequent encodings only need to:
/// 1. Scatter values into pre-allocated arrays using the cached mapping
/// 2. Run INTT + RNS + NTT (unavoidable, but the packing/rotation step is skipped)
///
/// Typical speedup: ~30-40% by eliminating diagonal packing and rotation computation.
public struct FastPlaintextEncoder<Scheme: HeScheme>: Sendable {
    /// One entry per input value: tells us where it goes in the SIMD arrays.
    public struct SlotMapping: Sendable {
        /// Which plaintext in the PlaintextMatrix this value belongs to.
        public let plaintextIndex: Int
        /// Which SIMD position within that plaintext's encoding array.
        public let simdSlotIndex: Int
        /// Index into the flat input values array.
        public let valueIndex: Int
    }

    /// The cached mapping from input values to SIMD slots.
    @usableFromInline let mappings: [SlotMapping]

    /// Number of plaintexts in the matrix.
    @usableFromInline let plaintextCount: Int

    /// Degree of each polynomial.
    @usableFromInline let polyDegree: Int

    /// The server config used to build this encoder.
    @usableFromInline let serverConfig: ServerConfig<Scheme>

    /// Matrix dimensions.
    @usableFromInline let dimensions: MatrixDimensions

    /// Database packing (cached from serverConfig).
    @usableFromInline let databasePacking: MatrixPacking

    /// Pre-computes the encoding map for a fixed database shape.
    ///
    /// - Parameters:
    ///   - config: Server configuration.
    ///   - context: HE context.
    ///   - rowCount: Number of database vectors (fixed).
    /// - Throws: Error if the config is incompatible.
    public init(config: ServerConfig<Scheme>, context: Scheme.Context, rowCount: Int) throws {
        self.serverConfig = config
        let encryptionParameters = context.encryptionParameters
        let vectorDimension = config.vectorDimension
        self.dimensions = try MatrixDimensions(rowCount: rowCount, columnCount: vectorDimension)
        self.polyDegree = encryptionParameters.polyDegree

        guard let simdDimensions = Scheme.simdDimensions(for: encryptionParameters) else {
            throw PnnsError.simdEncodingNotSupported(for: encryptionParameters)
        }
        guard case let .diagonal(bsgs) = config.databasePacking else {
            throw PnnsError.wrongMatrixPacking(
                got: config.databasePacking,
                expected: .diagonal(babyStepGiantStep: BabyStepGiantStep(
                    vectorDimension: vectorDimension)))
        }

        let simdEncodingMatrix = context.simdEncodingMatrix
        let n = polyDegree

        // Replay the diagonal packing logic to build the mapping.
        // This mirrors PlaintextMatrix.diagonalPlaintexts() but records
        // where each value lands instead of actually encoding.

        let packedRowCount = vectorDimension.nextPowerOfTwo
        let expectedPlaintextCount = try PlaintextMatrix<Scheme, Coeff>.plaintextCount(
            encryptionParameters: encryptionParameters,
            dimensions: dimensions,
            packing: config.databasePacking)
        let plaintextsPerColumn = expectedPlaintextCount / packedRowCount

        self.plaintextCount = expectedPlaintextCount

        var mappings: [SlotMapping] = []
        mappings.reserveCapacity(rowCount * vectorDimension)

        var plaintextCounter = 0
        for packedRowIndex in 0..<packedRowCount {
            // Build the logical row (after diagonal rotation)
            // Each row has `rowCount` elements, chunked into groups of `n`
            let row = (0..<rowCount).map { columnIndex -> (Int, Int)? in
                let paddedColumnIndex = (columnIndex &+ packedRowIndex) % packedRowCount
                if paddedColumnIndex < vectorDimension {
                    // This maps to input[columnIndex, paddedColumnIndex]
                    return (columnIndex, paddedColumnIndex)
                }
                return nil // zero-padded
            }

            for (chunkIndex, chunk) in row.chunks(ofCount: n).enumerated() {
                let plaintextIndex = plaintextCounter
                let i = (plaintextCounter - chunkIndex) / plaintextsPerColumn
                let rotationStep = i.previousMultiple(of: bsgs.babyStep, variableTime: true)

                // Apply BSGS rotation to determine final SIMD slot positions
                for (posInChunk, mapping) in chunk.enumerated() {
                    guard let (vectorIdx, dimIdx) = mapping else { continue }

                    // Apply the rotation (same logic as the rotate calls in diagonalPlaintexts)
                    var simdPos = posInChunk
                    if rotationStep != 0 {
                        let halfN = n / 2
                        if simdPos < halfN {
                            simdPos = (simdPos + rotationStep) % halfN
                        } else {
                            simdPos = halfN + (simdPos - halfN + rotationStep) % halfN
                        }
                    }

                    // Map through simdEncodingMatrix to get the actual polynomial coefficient position
                    let coeffPos = simdEncodingMatrix[simdPos]

                    mappings.append(SlotMapping(
                        plaintextIndex: plaintextIndex,
                        simdSlotIndex: coeffPos,
                        valueIndex: vectorIdx * vectorDimension + dimIdx))
                }

                plaintextCounter += 1
            }
        }

        self.databasePacking = config.databasePacking
        self.mappings = mappings
    }

    /// Encodes integer values into a PlaintextMatrix using the pre-computed mapping.
    ///
    /// Skips diagonal packing and rotation computation — only does scatter + NTT.
    ///
    /// - Parameters:
    ///   - signedValues: The quantized integer values (row-major, same layout as Database.rows vectors).
    ///   - context: HE context.
    /// - Returns: The encoded PlaintextMatrix in Eval format.
    /// - Throws: Error upon encoding failure.
    @inlinable
    public func encode(signedValues: [Scheme.SignedScalar],
                       context: Scheme.Context) throws -> PlaintextMatrix<Scheme, Eval>
    {
        let t = context.encryptionParameters.plaintextModulus

        // Step 1: Scatter values into SIMD arrays using pre-computed mapping
        var simdArrays: [Array2d<Scheme.Scalar>] = (0..<plaintextCount).map { _ in
            Array2d<Scheme.Scalar>.zero(rowCount: 1, columnCount: polyDegree)
        }

        for mapping in mappings {
            let signedVal = signedValues[mapping.valueIndex]
            // Convert signed to unsigned mod t
            let unsignedVal = signedVal >= 0
                ? Scheme.Scalar(signedVal)
                : Scheme.Scalar(Scheme.SignedScalar(t) + signedVal)
            simdArrays[mapping.plaintextIndex][0, mapping.simdSlotIndex] = unsignedVal
        }

        // Step 2: INTT + RNS expand + NTT for each plaintext (unavoidable)
        let plaintexts: [Plaintext<Scheme, Eval>] = try simdArrays.map { array in
            let evalPoly = PolyRq<Scheme.Scalar, Eval>(context: context.plaintextContext, data: array)
            let coeffPoly = try evalPoly.inverseNtt()
            let coeffPlaintext = try Plaintext<Scheme, Coeff>(context: context, poly: coeffPoly)
            return try coeffPlaintext.convertToEvalFormat()
        }

        return try PlaintextMatrix(
            dimensions: dimensions,
            packing: databasePacking,
            plaintexts: plaintexts)
    }

    /// Encodes a ``QuantizedDatabase`` into a ``ProcessedDatabase`` ready for HE queries.
    ///
    /// This is the fast path for the proxy architecture:
    /// 1. Proxy retrieves ``QuantizedDatabase`` from ORAM (~1.5MB)
    /// 2. Fast encoder produces ``ProcessedDatabase`` (~8ms in release mode)
    /// 3. Server computes on it (~33ms)
    ///
    /// - Parameters:
    ///   - quantizedDB: The compact quantized database.
    ///   - context: HE context.
    /// - Returns: A ``ProcessedDatabase`` ready for ``Server`` to compute on.
    /// - Throws: Error upon encoding failure.
    @inlinable
    public func encodeDatabase(
        _ quantizedDB: QuantizedDatabase<Scheme>,
        context: Scheme.Context) throws -> ProcessedDatabase<Scheme>
    {
        let plaintextMatrix = try encode(signedValues: quantizedDB.signedValues, context: context)
        return try ProcessedDatabase(
            contexts: [context],
            plaintextMatrices: [plaintextMatrix],
            entryIds: quantizedDB.entryIds,
            entryMetadatas: quantizedDB.entryMetadatas,
            serverConfig: serverConfig)
    }
}
