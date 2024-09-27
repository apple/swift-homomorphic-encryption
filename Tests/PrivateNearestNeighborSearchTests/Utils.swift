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

import Foundation
import HomomorphicEncryption
import PrivateNearestNeighborSearch

struct DatabaseConfig {
    let rowCount: Int
    let vectorDimension: Int
    let metadataCount: Int

    init(rowCount: Int, vectorDimension: Int, metadataCount: Int = 0) {
        self.rowCount = rowCount
        self.vectorDimension = vectorDimension
        self.metadataCount = metadataCount
    }
}

func getDatabaseForTesting(config: DatabaseConfig) -> Database {
    let rows = (0..<config.rowCount).map { rowIndex in
        let vector = (0..<config.vectorDimension).map { Float($0 + rowIndex) * (rowIndex.isMultiple(of: 2) ? 1 : -1) }
        let metadata = Array(repeating: UInt8(rowIndex % Int(UInt8.max)), count: config.metadataCount)
        return DatabaseRow(
            entryId: UInt64(rowIndex),
            entryMetadata: metadata,
            vector: vector)
    }
    return Database(rows: rows)
}

extension Array where Element: Collection, Element.Element: ScalarType, Element.Index == Int {
    typealias BaseElement = Element.Element

    func mul(_ vector: [BaseElement], modulus: BaseElement) throws -> [BaseElement] {
        map { row in
            precondition(row.count == vector.count)
            return zip(row, vector).reduce(0) { sum, multiplicands in
                let product = multiplicands.0.multiplyMod(multiplicands.1, modulus: modulus, variableTime: true)
                return sum.addMod(product, modulus: modulus)
            }
        }
    }
}
