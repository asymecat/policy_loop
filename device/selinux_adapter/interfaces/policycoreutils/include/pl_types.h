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

#ifndef POLICY_LOOP_PL_TYPES_H
#define POLICY_LOOP_PL_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace policy_loop {

/*
 * Shared vocabulary for the on-device AVC convergence tool.
 *
 * Every field mirrors a Python field in policy_loop/denial/parser.py,
 * policy_loop/policy/index.py and policy_loop/converge.py. The device must reach
 * the same verdicts as the host engine, so where Python encodes a third state
 * through None this header encodes it explicitly rather than collapsing it --
 * each such place is called out below.
 */

// --------------------------------------------------------------------------
// Optional string
// --------------------------------------------------------------------------

/*
 * A string that can be *absent* as well as empty.
 *
 * Python's parser returns None for a missing field, but can also return ""
 * (e.g. `scontext=foo` splits to ["foo"] and yields a present-but-empty type).
 * fingerprint() serializes those differently ("null" vs "\"\""), so collapsing
 * them here would merge two distinct denials into one cluster.
 */
struct OptStr {
    std::string value;
    bool present = false;

    OptStr() = default;
    OptStr(const char *v) : value(v == nullptr ? "" : v), present(v != nullptr) {}
    explicit OptStr(std::string v) : value(std::move(v)), present(true) {}

    bool operator==(const OptStr &other) const
    {
        return present == other.present && (!present || value == other.value);
    }
    bool operator!=(const OptStr &other) const
    {
        return !(*this == other);
    }
};

// --------------------------------------------------------------------------
// Denial records
// --------------------------------------------------------------------------

/*
 * Tri-state `permissive=` flag. Python uses Optional[bool]; an absent flag and
 * `permissive=2` both give None, which converge.py routes to
 * DOMAIN_OR_LABEL_MISMATCH rather than down the enforcing path, so the third
 * state must stay distinguishable.
 */
enum class Permissive : int8_t {
    kUnknown = -1,
    kEnforcing = 0,
    kPermissive = 1,
};

/*
 * One structured `avc: denied` event. Field-for-field the Python DenialRecord.
 */
struct DenialRecord {
    std::string raw;                        // event text, stripped (Python .strip())
    OptStr source_domain;                   // scontext type
    OptStr target_type;                     // tcontext type
    OptStr tclass;
    std::vector<std::string> permissions;   // *log order*; fingerprint() sorts
    Permissive permissive = Permissive::kUnknown;
    OptStr comm;
    bool hasPid = false;
    long long pid = 0;
    OptStr path;
    OptStr name;
    OptStr ioctlCmd;
    OptStr parameter;
    OptStr service;
};

// --------------------------------------------------------------------------
// Policy rules
// --------------------------------------------------------------------------

enum class RuleKind : uint8_t {
    kAllow,
    kNeverAllow,
    kAllowXperm,
    kNeverAllowXperm,
};

inline bool IsXperm(RuleKind kind)
{
    return kind == RuleKind::kAllowXperm || kind == RuleKind::kNeverAllowXperm;
}

inline bool IsNeverAllow(RuleKind kind)
{
    return kind == RuleKind::kNeverAllow || kind == RuleKind::kNeverAllowXperm;
}

inline const char *RuleKindName(RuleKind kind)
{
    switch (kind) {
        case RuleKind::kAllow: return "allow";
        case RuleKind::kNeverAllow: return "neverallow";
        case RuleKind::kAllowXperm: return "allowxperm";
        case RuleKind::kNeverAllowXperm: return "neverallowxperm";
    }
    return "?";
}

} // namespace policy_loop

#endif // POLICY_LOOP_PL_TYPES_H
