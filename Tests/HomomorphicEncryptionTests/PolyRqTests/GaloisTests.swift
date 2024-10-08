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
import TestUtilities
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

    func testGaloisElementsToSteps() throws {
        let galoisElements = [2, 3, 9, 11]
        let degree = 8
        let result = GaloisElement.stepsFor(elements: galoisElements, degree: degree)
        let expected = [2: nil, 3: 3, 9: 2, 11: 1]
        XCTAssertEqual(result, expected)

        // roundtrip
        for degree in [16, 32, 1024] {
            let steps = 1..<degree / 2
            var elementToStep: [Int: Int] = [:]
            for step in steps {
                try elementToStep[GaloisElement.rotatingColumns(by: step, degree: degree)] = step
            }

            let result = GaloisElement.stepsFor(elements: Array(elementToStep.keys), degree: degree)
            XCTAssertEqual(result, elementToStep)
        }
    }

    func testPlanMultiStepSmall() throws {
        let degree = 32

        do {
            // No plan found.
            let supportedSteps = [2, 4, 8]
            for step in [1, 3, 5, 7, 9, 11, 13, 15] {
                let plan = try GaloisElement.planMultiStep(supportedSteps: supportedSteps, step: step, degree: degree)
                XCTAssertNil(plan)
            }
        }

        do {
            // Positive steps are always cheaper.
            let supportedSteps = [1, 4, 8]
            let transformNegative: (Int) -> Int = { step in
                (degree >> 1) - step
            }
            let negativeSteps = supportedSteps.map { step in
                transformNegative(step)
            }

            let knownAnswers = [
                (1, [1: 1]),
                (2, [1: 2]),
                (3, [1: 3]),
                (4, [4: 1]),
                (4, [4: 1]),
                (5, [4: 1, 1: 1]),
                (6, [4: 1, 1: 2]),
                (7, [4: 1, 1: 3]),
                (8, [8: 1]),
                (9, [8: 1, 1: 1]),
                (10, [8: 1, 1: 2]),
                (11, [8: 1, 1: 3]),
                (12, [8: 1, 4: 1]),
                (13, [8: 1, 4: 1, 1: 1]),
                (14, [8: 1, 4: 1, 1: 2]),
                (15, [8: 1, 4: 1, 1: 3]),
            ]

            for (step, counts) in knownAnswers {
                var result = try GaloisElement.planMultiStep(supportedSteps: supportedSteps, step: step, degree: degree)
                XCTAssertEqual(result, counts)

                // Negative steps yields same plan, just with negative rotations.
                let negativeStep = transformNegative(step)
                let negativeStepCounts = Dictionary(uniqueKeysWithValues: counts.map { step, count in
                    (transformNegative(step), count)
                })

                result = try GaloisElement.planMultiStep(
                    supportedSteps: negativeSteps,
                    step: negativeStep,
                    degree: degree)
                XCTAssertEqual(result, negativeStepCounts)
            }
        }

        do {
            // Positive or negative steps may be cheaper.
            let supportedSteps = [1, 2, 6, 12, 15]
            let knownAnswers = [
                (4, [2: 2]), // Positive steps are cheaper.
                (11, [12: 1, 15: 1]), // Negative steps are cheaper.
            ]

            for (step, counts) in knownAnswers {
                let result = try GaloisElement.planMultiStep(supportedSteps: supportedSteps, step: step, degree: degree)
                XCTAssertEqual(result, counts)
            }
        }
    }

    func testMultiStepBig() throws {
        let degree = 8192
        let transformPositive: (Int) -> Int = { step in
            var step = step
            if step < 0 {
                step += degree / 2
            }
            return step
        }
        let steps = [1, transformPositive(-1), transformPositive(-16), transformPositive(-256)]
        let knownAnswers = [
            (transformPositive(-15), [transformPositive(-16): 1, 1: 1]),
            (transformPositive(-191), [transformPositive(-16): 11,
                                       transformPositive(-1): 15]),
            (transformPositive(-192), [transformPositive(-16): 12]),
        ]
        for (step, counts) in knownAnswers {
            let result = try GaloisElement.planMultiStep(supportedSteps: steps, step: step, degree: degree)
            XCTAssertEqual(result, counts)
        }
    }
}
