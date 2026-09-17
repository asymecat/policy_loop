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

#ifndef POLICY_LOOP_PL_AVC_PARSER_H
#define POLICY_LOOP_PL_AVC_PARSER_H

#include <string>
#include <vector>

#include "pl_types.h"

namespace policy_loop {

/*
 * Port of policy_loop/denial/parser.py.
 *
 * Hand-written scanner rather than std::regex. The upstream patterns lean on
 * backtracking subtleties -- a lazy `[^}]*?` for the permission set, an
 * alternation whose quoted branch must fall back to a bare `[^\s,]+`, and a
 * `\b` boundary on the event marker -- and reproducing those exactly is easier
 * to reason about (and to review) as explicit scanning loops than as a
 * translation into another regex dialect. std::regex is also unusable on the
 * device image.
 *
 * Fidelity is a hard acceptance metric: the differential harness compares this
 * parser's output field by field against the Python one over the real corpus.
 */

/*
 * Parse a chunk of log text into denial records.
 *
 * Each `avc: denied` occurrence opens a new record; the remainder of that line
 * block belongs to the same event. Records whose block contains only blank or
 * comment lines are dropped, which is how upstream `.te` fixtures carrying real
 * denials as `#` comments are still parsed.
 */
std::vector<DenialRecord> ParseDenials(const std::string &text);

/*
 * The exact JSON byte string Fingerprint() hashes.
 *
 * Exposed separately so the differential harness can diff the payload across
 * host and device: when a digest disagrees, the payload says *which field* did.
 */
std::string FingerprintPayload(const DenialRecord &rec);

/*
 * Canonical dedup key of one denial: the *logical access* it reports.
 * sha1(payload).hexdigest()[:12], byte-identical to the Python implementation.
 *
 * Because the device's input is sampled (the kernel rate-limits the audit
 * printk path to 10 messages / 5 s), duplicate suppression by fingerprint is
 * what makes `unique_cases` a stable acceptance metric where a raw denial count
 * is not.
 */
std::string Fingerprint(const DenialRecord &rec);

/*
 * Escape *value* as a JSON string literal (quotes included), with the same
 * escaping rules as Python's json.dumps(..., ensure_ascii=False).
 *
 * Shared with the report writer so that a host/device diff of any emitted JSON
 * compares like for like; a second escaper written independently is exactly the
 * kind of thing that silently disagrees on one nasty input.
 */
std::string JsonString(const std::string &value);

} // namespace policy_loop

#endif // POLICY_LOOP_PL_AVC_PARSER_H
