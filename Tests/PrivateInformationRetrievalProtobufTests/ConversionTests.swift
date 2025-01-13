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

import _CryptoExtras
import Crypto
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

    func testOprfQuery() throws {
        let element =
            "02a36bc90e6db34096346eaf8b7bc40ee1113582155ad3797003ce614c835a874343701d3f2debbd80d97cbe45de6e5f1f"
        let query = try OprfQuery(oprfRepresentation: Data(XCTUnwrap(Array(hexEncoded: element))))
        let roundTrip = try query.proto().native()
        XCTAssertEqual(roundTrip.oprfRepresentation, query.oprfRepresentation)
    }

    func testOprfResponse() throws {
        let evaluatedElement =
            try Data(
                XCTUnwrap(Array(
                    hexEncoded: """
                        02a7bba589b3e8672aa19e8fd258de2e6aae20101c8d761246de97a6b5ee9cf105febce4327a326\
                        255a3c604f63f600ef6
                        """)))

        let proof =
            try Data(
                XCTUnwrap(Array(
                    hexEncoded: """
                        bfc6cf3859127f5fe25548859856d6b7fa1c7459f0ba5712a806fc091a3000c42d8ba34ff45f32a52\
                        e40533efd2a03bc87f3bf4f9f58028297ccb9ccb18ae7182bcd1ef239df77e3be65ef147f3acf8bc9\
                        cbfc5524b702263414f043e3b7ca2e
                        """)))
        let rawRepresentation = evaluatedElement + proof
        let blindEvaluation = try OprfResponse(rawRepresentation: rawRepresentation)
        XCTAssertEqual(try blindEvaluation.proto().native().rawRepresentation, blindEvaluation.rawRepresentation)
    }

    func testKeywordPirParameter() throws {
        var keywordPirParameter = KeywordPirParameter(hashFunctionCount: 2)
        var roundTrip = keywordPirParameter.proto().native()
        XCTAssertEqual(roundTrip, keywordPirParameter)
        let symmetricPirClientConfig = SymmetricPirClientConfig(serverPublicKey: [],
                                                                configType: .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128)
        keywordPirParameter = KeywordPirParameter(hashFunctionCount: 2,
                                                  symmetricPirClientConfig: symmetricPirClientConfig)
        roundTrip = try keywordPirParameter.proto().nativeWithSymmetricPirClientConfig()
        XCTAssertEqual(roundTrip, keywordPirParameter)
    }
}
