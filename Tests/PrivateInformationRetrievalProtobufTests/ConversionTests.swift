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

@testable import HomomorphicEncryption
@testable import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf

import TestUtilities
import XCTest

class ConversionTests: XCTestCase {
    func testKeywordDatabase() throws {
        let rowCount = 10
        let payloadSize = 5
        let databaseRows = (0..<rowCount).map { index in KeywordValuePair(
            keyword: [UInt8](String(index).utf8),
            value: (0..<payloadSize).map { _ in UInt8.random(in: 0..<UInt8.max) })
        }

        let proto = databaseRows.proto()
        XCTAssertEqual(proto.rows.count, rowCount)
        XCTAssert(proto.rows.map(\.value).allSatisfy { $0.count == payloadSize })
        let native = proto.native()

        XCTAssertEqual(native, databaseRows)
    }

    func testProcessedDatabaseWithParameters() throws {
        let rows = (0..<10).map { KeywordValuePair(keyword: Array(String($0).utf8), value: Array(String($0).utf8)) }
        let context: Context<Bfv<UInt32>> = try .init(encryptionParameters: .init(from: .n_4096_logq_27_28_28_logt_13))
        let config = try KeywordPirConfig(
            dimensionCount: 2,
            cuckooTableConfig: .defaultKeywordPir(maxSerializedBucketSize: context.bytesPerPlaintext),
            unevenDimensions: true,
            keyCompression: .noCompression)
        let processedDatabaseWithParameters = try KeywordPirServer<MulPirServer<Bfv<UInt32>>>.process(
            database: rows,
            config: config,
            with: context)

        let processedDatabase = processedDatabaseWithParameters.database

        let pirParameters = try processedDatabaseWithParameters.proto(context: context)
        let loadedProcessedDatabaseWithParameters = try pirParameters.native(database: processedDatabase)
        XCTAssertEqual(loadedProcessedDatabaseWithParameters, processedDatabaseWithParameters)
    }

    func testPirAlgorithm() throws {
        for algorithm in PirAlgorithm.allCases {
            XCTAssertEqual(try algorithm.proto().native(), algorithm)
        }
    }

    func testPirKeyCompressionStrategy() throws {
        for strategy in PirKeyCompressionStrategy.allCases {
            XCTAssertEqual(try strategy.proto().native(), strategy)
        }
    }
}
