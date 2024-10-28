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

import HomomorphicEncryption

let m = Modulus(modulus: UInt64(13), variableTime: true)
/// merely ensuring `Modulus`  type is available when importing
/// `HomomorphicEncryption`
print("m", m)
precondition(m.multiplyMod(5, 10) == 11)
precondition(UInt64(5).addMod(10, modulus: m.modulus) == 2)
precondition(m.dividingFloor(dividend: UInt64(100)) == 7)
