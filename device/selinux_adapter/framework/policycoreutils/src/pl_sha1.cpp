/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pl_sha1.h"

#include <cstdint>
#include <cstring>

namespace policy_loop {
namespace {

inline uint32_t Rotl(uint32_t value, int bits)
{
    return (value << bits) | (value >> (32 - bits));
}

void Sha1Block(const uint8_t *block, uint32_t state[5])
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = Rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f = 0;
        uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t tmp = Rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = Rotl(b, 30);
        b = a;
        a = tmp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

} // namespace

std::string Sha1Hex(const void *data, size_t len)
{
    uint32_t state[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    const uint8_t *bytes = static_cast<const uint8_t *>(data);

    size_t whole = len / 64;
    for (size_t i = 0; i < whole; ++i) {
        Sha1Block(bytes + i * 64, state);
    }

    // Padding: 0x80, zeros, then the bit length big-endian in the last 8 bytes.
    // One extra block is needed when the remainder leaves no room for the length.
    uint8_t tail[128];
    size_t rem = len - whole * 64;
    if (rem > 0) {
        std::memcpy(tail, bytes + whole * 64, rem);
    }
    tail[rem] = 0x80;
    size_t tailLen = (rem < 56) ? 64 : 128;
    std::memset(tail + rem + 1, 0, tailLen - rem - 1);
    uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int i = 0; i < 8; ++i) {
        tail[tailLen - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
    }
    Sha1Block(tail, state);
    if (tailLen == 128) {
        Sha1Block(tail + 64, state);
    }

    static const char *kHex = "0123456789abcdef";
    std::string out;
    out.reserve(40);
    for (int i = 0; i < 5; ++i) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            uint8_t byte = static_cast<uint8_t>(state[i] >> shift);
            out.push_back(kHex[byte >> 4]);
            out.push_back(kHex[byte & 0x0F]);
        }
    }
    return out;
}

std::string Sha1Hex(const std::string &data)
{
    return Sha1Hex(data.data(), data.size());
}

} // namespace policy_loop
