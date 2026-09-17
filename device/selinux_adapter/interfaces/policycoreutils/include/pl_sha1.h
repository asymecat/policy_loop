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

#ifndef POLICY_LOOP_PL_SHA1_H
#define POLICY_LOOP_PL_SHA1_H

#include <cstddef>
#include <string>

namespace policy_loop {

/*
 * SHA-1 (FIPS 180-1), one-shot.
 *
 * Implemented locally rather than linked from libcrypto: the device tool keeps
 * its dynamic dependencies to libc/libc++/libm, and the single use is the
 * 12-hex-char denial fingerprint, which must equal Python's
 * ``hashlib.sha1(...).hexdigest()[:12]`` byte for byte (see
 * ``policy_loop/denial/parser.py:fingerprint``). The differential harness
 * compares fingerprints across host and device, so any deviation here surfaces
 * as every cluster failing to pair up.
 */
std::string Sha1Hex(const void *data, size_t len);
std::string Sha1Hex(const std::string &data);

} // namespace policy_loop

#endif // POLICY_LOOP_PL_SHA1_H
