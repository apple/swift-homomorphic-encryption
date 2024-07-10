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

#include <string.h>
#include <zeroize.h>

void c_zeroize(void *s, size_t n)
{
    // We'd prefer to use memset_s if possible, since the compiler shouldn't optimize that away.
    // If it's not available, we use a memory barrier as a best effort to prevent optimization
    memset(s, 0, n);
    __asm__ __volatile__("" : : "r"(s) : "memory");
}
