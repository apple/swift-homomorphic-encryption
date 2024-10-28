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

import ModularArithmetic

func useProtocols<T1: CoreScalarType, T2: CoreSignedScalarType>(
    unsignedV1: T1,
    signedV2: T2) -> (T1, T2)
{
    let reminder1 = unsignedV1.toRemainder(11, variableTime: true)
    let lessThan1 = reminder1.constantTimeLessThan(5)
    let reminder2 = signedV2.toRemainder(97, variableTime: true)
    let lessThan2 = reminder2.multiplyHigh(48)
    return (lessThan1, lessThan2)
}

let v1: UInt32 = 5
let v2: Int32 = -33

precondition(useProtocols(unsignedV1: v1, signedV2: v2) == (0, 0))

let modulus: UInt32 = 13
let singleWordModulus = ReduceModulus(
    modulus: modulus,
    bound: ReduceModulus.InputBound.SingleWord,
    variableTime: true)
let doubleWordModulus = ReduceModulus(
    modulus: modulus,
    bound: ReduceModulus.InputBound.DoubleWord,
    variableTime: true)
let reduceProductModulus = ReduceModulus(
    modulus: modulus,
    bound: ReduceModulus.InputBound.ModulusSquared,
    variableTime: true)
let divisionModulus = DivisionModulus(
    modulus: modulus,
    singleFactor: UInt32(991_146_300),
    doubleFactor: UInt64(4_256_940_940_086_819_604))
let m = Modulus(modulus: modulus,
                singleWordModulus: singleWordModulus,
                doubleWordModulus: doubleWordModulus,
                reduceProductModulus: reduceProductModulus,
                divisionModulus: divisionModulus)

precondition(m.multiplyMod(4, 5) == 7)
print("4 * 5 mod \(modulus) = \(m.multiplyMod(4, 5))")
