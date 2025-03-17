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

@testable import HomomorphicEncryption
import Testing
import TestUtilities

@Suite
struct NistCtrDrbgTests {
    @Test
    func vector() throws {
        // Test vectors adapted from:
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators
        let entropy =
            try #require(Array(hexEncoded: "69a09f6bf5dda15cd4af29e14cf5e0cddd7d07ac39bba587f8bc331104f9c448"))
        let expected = try #require(Array(hexEncoded:
            """
            f78a4919a6ec899f7b6c69381febbbe083315f3d289e70346db0e4ec4360473ae0b3\
            d916e9b6b964309f753ed66ae59de48da316cc1944bc8dfd0e2575d0ff6d
            """))

        var prng = try NistCtrDrbg(entropy: entropy)

        func expectKey(_ hexString: String) {
            prng.key.withUnsafeBytes { keyBytes in
                let data = Array(keyBytes)
                #expect(data.hexEncodedString() == hexString)
            }
        }

        func expectNonce(_ hexString: String) {
            #expect(Array(prng.nonce.bigEndianBytes).hexEncodedString() == hexString)
        }

        expectKey("314263a50fa3913de2d034b6e812a597")
        expectNonce("def5dd62590d06150b94f1a8754b3a30")
        _ = try prng.ctrDrbgGenerate(count: expected.count)
        expectKey("4b0f2ae7d0b330fa709b0844c7eedb5c")
        expectNonce("dae190eb55353de50e494cdef2a544d4")
        let output = try prng.ctrDrbgGenerate(count: expected.count)
        expectKey("b4d5d6de074612076e496f241ebcf017")
        expectNonce("034eeae49adbdfccff79bfdc0d83ed70")
        #expect(output == expected)
    }

    @Test
    func vectors() throws {
        // (entropy, returnedbits)
        let vectors = [
            (
                "69a09f6bf5dda15cd4af29e14cf5e0cddd7d07ac39bba587f8bc331104f9c448",
                """
                f78a4919a6ec899f7b6c69381febbbe083315f3d289e70346db0e4ec4360473a\
                e0b3d916e9b6b964309f753ed66ae59de48da316cc1944bc8dfd0e2575d0ff6d
                """),
            (
                "80bfbd340d79888f34f043ed6807a9f28b72b6644d9d9e9d777109482b80788a",
                """
                80db048d2f130d864b19bfc547c92503e580cb1a8e1f74f3d97fdda6501fb1aa\
                81fcedac0dd18b6ccfdc183ca28a44fc9f3a08834ba8751a2f4495367c54a185
                """),
            (
                "a559ac9872791d79197e54da70a8d858fbe39e8514d2c86a7bcffadc68782edf",
                """
                d14b72e17c2f6f77b46d0717b788420e503bb18de542135f586a90c5c73fceee\
                e50fd1633b5b09ab061b9367ca785ecb400e1f3681583661aaf8352184454ae6
                """),
            (
                "300fe148dd39de1edb993ca5260373b3f5f09a5cf7a32b0c41fe6224f981d3b1",
                """
                deea89b5128fb992696d7b97ebc2c0793614b172f4c75bb83c12a1b389bac3bf\
                ecb773cd7717583c2b61b3b243ac9683dba4fbc07182bad8271a7f16d833e4d9
                """),
            (
                "0c6ee2a5d46325baa8e9a3f6b598fc790c513d387d47001116d19a614d2038c4",
                """
                f1ee11be189263fed9932c1192219d00378e36ce81a431318545da9f81f50c29\
                13d1f7be499ce9e1e39f93ee2360668f127340691c17711707cf5f1f8a4d93ee
                """),
            (
                "bdbba1ad4803fdc783ef5d6e2aa66dc948e960bc11cca89a60cff5c60e984302",
                """
                260a32c3973750e0c10f7f7495d46e7c3691c27a58e828cdef48ef660716f771\
                d61c3c76db407d816066f5afbf16993485cdb653d418dd65ffa5d3825732b8cb
                """),
            (
                "22587bfdce62f4afc1dd2673f5308364f27db9912ad01b045e74db4518435959",
                """
                c904d03089b7dd1f17564a7ef70b17bb1b29c0c1793cc8d92b8c158c04ca5366\
                919f8caf544d5d07c28abe6d14baaa0c56602df1c373e9acc419e3c932e577e6
                """),
            (
                "8abefbb23dfd58d82b88a4c4fcfcee183ce01db975edeeb404bd216e6177ea0d",
                """
                8a708e8a99035389a4d66d57d12f488ecba57a3b2ca78015bedae06aaa414d79\
                1196e262b28fbd745dff94f8fe600687c9ce2f50cf6d79d39b8c5ea36533755d
                """),
            (
                "c45c9fec6bb83fb08008877c70b632d792119a35c4c5988c4026cf3f8612b800",
                """
                84430e49a9b4d395d055ca0efdf285a7551c5f7119dbea5c10daaa9e8be041e2\
                3e9bc893c90a35b77b19dc202ec834172e6c8cea97c9d7c68df1374aeea94537
                """),
            (
                "58cbccd7f86e5f0472dcb377f598f2d42ed96afdf0c8e45f12c4ff4a969c5b6b",
                """
                41ff55d058beaa04308bd0b39d4801f70f23d829037e4cc9b2ea0eacf5aef9b8\
                e33fc59c528b53bce08d2b536d37bf194c797f03290494dd00ef244ac223e350
                """),
            (
                "d50558dfb7a8966c63b3a1d0a837970ad0bff5adbd8adacae5d3accfde64cd4d",
                """
                e91361511d926be4d997fc970b1a5dcdb33a711f215cbdbffabfcdaa62485968\
                91d55a9e64f4e9f5185ed7056f7cbb42f474a23542fe9e9c2495182cefb38a6a
                """),
            (
                "f70ce283efd5ba36c284cb267d22e23dc41671b2aaae98e638c6e451bc9c3cbb",
                """
                fd9b3b53e12b6702e4c6e4acac33aeae5ceb34cebfffa7007cb1ab1c3b4be1a3\
                8e5c86dea0775ab0c89ae135e0b36da087921d3ff275ffc8e5dcee6e3d66ee43
                """),
            (
                "58eb544f44dfe1048a8113d4b6909050abf9010036233be7f8fcc41f39baff9c",
                """
                5c6aedc020e764f4d3bb8abc2907c9c604dd98e1cfc2882ea72d554e39fe8646\
                3a51886d980ac8cdda0f4e584226d45344e43dd84e8430f58c3880a0ce930863
                """),
            (
                "b694ce5f4d9af4ce93626636c9ecb341f3f5152fd580745202cd0c83f4d5b4c5",
                """
                78b32d396f5a919f5ccb9be2afaf5f6212d75bf084e99357e28ccc98d43369645\
                5b10a85ecaf61686a96606ff3e8962321358a56fa53cabbf16c65c1c32debcd
                """),
            (
                "42cb183d2a04c89c69efbcec08bee2003b9a1cd56878a774f0162bf70f2c708f",
                """
                cb4afdec033b42949ebbb27245fd33c1503c1278027e11a1f050e04080abe485\
                0821b71ed5a6bd83da6bde8e56c5faed49da26887028bab807d1ad055e2a8a27
                """),
        ]

        for (entropyString, outputString) in vectors {
            let entropy = try #require(Array(hexEncoded: entropyString))
            let expected = try #require(Array(hexEncoded: outputString))

            var prng = try NistCtrDrbg(entropy: entropy)
            _ = try prng.ctrDrbgGenerate(count: expected.count)
            let output = try prng.ctrDrbgGenerate(count: expected.count)
            #expect(output == expected)
        }
    }
}
