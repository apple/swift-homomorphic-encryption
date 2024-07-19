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
import XCTest

final class GaloisTests: XCTestCase {
    private func getTestPolyWithElement3Degree4Moduli1<T>() throws -> (PolyRq<T, Coeff>, PolyRq<T, Coeff>) {
        let degree = 4
        let moduli: [T] = [17]
        let plaintextPolyContext = try PolyContext(degree: degree, moduli: moduli)
        let data: Array2d<T> = Array2d(data: [0, 1, 2, 3], rowCount: 1, columnCount: 4)
        let expectedAata: Array2d<T> = Array2d(data: [0, 3, 15, 1], rowCount: 1, columnCount: 4)
        let poly = PolyRq<T, Coeff>(context: plaintextPolyContext, data: data)
        let expectedPoly = PolyRq<T, Coeff>(context: plaintextPolyContext, data: expectedAata)
        return (poly, expectedPoly)
    }

    private func getTestPolyWithElement3Degree8Moduli1<T>() throws -> (PolyRq<T, Coeff>, PolyRq<T, Coeff>) {
        let degree = 8
        let moduli: [T] = [17]
        let plaintextPolyContext = try PolyContext(degree: degree, moduli: moduli)
        let data: Array2d<T> = Array2d(data: [0, 1, 2, 3, 4, 5, 6, 7], rowCount: 1, columnCount: 8)
        let expectedAata: Array2d<T> = Array2d(data: [0, 14, 6, 1, 13, 7, 2, 12], rowCount: 1, columnCount: 8)
        let poly = PolyRq<T, Coeff>(context: plaintextPolyContext, data: data)
        let expectedPoly = PolyRq<T, Coeff>(context: plaintextPolyContext, data: expectedAata)
        return (poly, expectedPoly)
    }

    private func getTestPolyWithElement3Degree8Moduli2<T>() throws -> (PolyRq<T, Coeff>, PolyRq<T, Coeff>) {
        let degree = 8
        let moduli: [T] = [17, 97]
        let plaintextPolyContext = try PolyContext(degree: degree, moduli: moduli)
        let data: Array2d<T> = Array2d(
            data: [0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0],
            rowCount: 2,
            columnCount: 8)
        let expectedAata: Array2d<T> = Array2d(
            data: [0, 14, 6, 1, 13, 7, 2, 12, 7, 93, 1, 6, 94, 0, 5, 95],
            rowCount: 2,
            columnCount: 8)
        let poly = PolyRq<T, Coeff>(context: plaintextPolyContext, data: data)
        let expectedPoly = PolyRq<T, Coeff>(context: plaintextPolyContext, data: expectedAata)
        return (poly, expectedPoly)
    }

    private func applyGaloisTestHelper<T>(_: T.Type, getFunc: () throws -> (
        PolyRq<T, Coeff>,
        PolyRq<T, Coeff>)) throws
    {
        let (poly, expectedPoly) = try getFunc()
        XCTAssertEqual(poly.applyGalois(element: 3), expectedPoly)
        XCTAssertEqual(try poly.forwardNtt().applyGalois(element: 3).inverseNtt(), expectedPoly)
        for index in 1..<poly.degree {
            let element = index * 2 + 1
            XCTAssertEqual(try poly.applyGalois(element: element).forwardNtt(),
                           try poly.forwardNtt().applyGalois(element: element))
        }

        let forwardElement = GaloisElement.swappingRows(degree: poly.degree)
        XCTAssertEqual(
            poly.applyGalois(element: forwardElement).applyGalois(element: forwardElement),
            poly)
        XCTAssertEqual(
            try poly.forwardNtt().applyGalois(element: forwardElement)
                .applyGalois(element: forwardElement),
            try poly.forwardNtt())

        for step in 1..<(poly.degree >> 1) {
            let inverseStep = (poly.degree >> 1) - step
            let forwardElement = try GaloisElement.rotatingColumns(by: step, degree: poly.degree)
            let backwardElement = try GaloisElement.rotatingColumns(by: inverseStep, degree: poly.degree)
            XCTAssertEqual(
                poly.applyGalois(element: forwardElement).applyGalois(element: backwardElement),
                poly)

            XCTAssertEqual(
                try poly.forwardNtt().applyGalois(element: forwardElement)
                    .applyGalois(element: backwardElement),
                try poly.forwardNtt())
        }
    }

    private func testApplyGaloisForType(type: (some ScalarType).Type) throws {
        try applyGaloisTestHelper(type, getFunc: getTestPolyWithElement3Degree4Moduli1)
        try applyGaloisTestHelper(type, getFunc: getTestPolyWithElement3Degree8Moduli1)
        try applyGaloisTestHelper(type, getFunc: getTestPolyWithElement3Degree8Moduli2)
    }

    func testApplyGalois() throws {
        try testApplyGaloisForType(type: UInt32.self)
        try testApplyGaloisForType(type: UInt64.self)
    }
}
