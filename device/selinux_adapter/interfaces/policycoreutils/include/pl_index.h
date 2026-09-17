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

#ifndef POLICY_LOOP_PL_INDEX_H
#define POLICY_LOOP_PL_INDEX_H

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "pl_types.h"

namespace policy_loop {

/*
 * The policy index, loaded from a PLI v1 file and queried with the same
 * semantics as policy_loop/policy/index.py.
 *
 * The device never parses `.te` sources: `.te` files do not ship on the device
 * at all, and a Release image carries no CIL either. The index is exported on
 * the host from the same sepolicy tree the firmware was built from, so a
 * verdict reached here is the verdict the host engine would reach.
 *
 * Symbols (types, attributes, classes, permissions) are interned to 32-bit ids
 * and every per-rule list is kept sorted, which turns the set operations in
 * `_matches` into binary searches. Attribute closures come pre-expanded from
 * the exporter: expanding them into rules instead would blow the payload up by
 * an order of magnitude.
 */

using SymId = uint32_t;
constexpr SymId kNoSym = 0xFFFFFFFFu;

struct PlRule {
    RuleKind kind = RuleKind::kAllow;
    SymId cls = kNoSym;
    std::vector<SymId> src;         // sorted, deduped
    std::vector<SymId> srcNeg;
    std::vector<SymId> tgt;
    std::vector<SymId> tgtNeg;
    bool srcStar = false;
    bool tgtStar = false;
    std::vector<SymId> perms;       // sorted, deduped; empty == wildcard
    SymId xpermPerm = kNoSym;       // kNoSym only for allow/neverallow
    std::vector<SymId> xperms;      // sorted, deduped, opaque tokens
    bool xpermInvert = false;
    std::string raw;                // the PLI line, for reporting
};

struct IndexMeta {
    long long rules = 0;
    long long allow = 0;
    long long neverallow = 0;
    long long allowxperm = 0;
    long long neverallowxperm = 0;
    long long types = 0;
    long long attrs = 0;
    long long classes = 0;
    long long perms = 0;
    long long known = 0;
    long long skipped = 0;          // not derivable from PLI; reported, not checked
    std::string source;
    std::string generated;
};

// Outcome of an ioctl query. `reason` points at a string literal so it can be
// compared by pointer and printed without allocation.
struct IoctlVerdict {
    bool allowed = false;
    const char *reason = "no_allow";
};

class PlIndex {
public:
    /*
     * Parse PLI v1 text. Returns nullptr and fills *err on a malformed header or
     * a failed self-check.
     *
     * The self-check (every @meta counter re-derived from the rule lines) is the
     * point of the format: if the payload were truncated in transfer, every
     * answer downstream would be quietly wrong, so a mismatch must be a hard
     * failure rather than a warning.
     */
    static std::unique_ptr<PlIndex> LoadFromText(const std::string &text, std::string *err);

    // Reads the file, then LoadFromText. Kept off the log-source abstraction:
    // the index is not a log, and this is the only place it is read.
    static std::unique_ptr<PlIndex> LoadFile(const std::string &path, std::string *err);

    const IndexMeta &meta() const { return meta_; }
    const std::string &symName(SymId id) const { return syms_[id]; }

    /*
     * sha1(payload)[:12] -- the same content-hash convention as the denial
     * fingerprint. `@meta source`/`@meta generated` already name the sepolicy
     * tree the index was exported from, but only a hash of the bytes identifies
     * the exact revision a verdict was reached against, which is what a report
     * has to be reproducible against.
     */
    const std::string &rev() const { return rev_; }

    // Symbol lookup that does *not* add to the table -- used for query inputs,
    // so that an unknown token simply never matches rather than growing the
    // index. Returns kNoSym when absent.
    SymId FindSym(const std::string &name) const;

    // Interns, adding when absent. Used when loading rules and when a caller
    // needs to compare log-supplied tokens (permissions, ioctl commands)
    // against indexed ones.
    SymId Intern(const std::string &name);

    // Transitive ancestor attributes, pre-expanded by the exporter. Unknown
    // identifiers yield an empty set, matching Python's type_attrs.get(n, ()).
    const std::vector<SymId> &Attrs(SymId ident) const;

    bool IsKnownToken(SymId id) const { return known_.count(id) != 0; }
    bool IsKnownClass(SymId id) const { return classes_.count(id) != 0; }
    bool IsDeclaredTypeOrAttr(const std::string &name) const;

    /*
     * The object classes the loaded rules actually mention.
     *
     * Not the same thing as IsKnownClass, which queries the exporter's `@class`
     * list: index.py's `_known_tokens` builds its `classes` from the classes
     * rules name, and the guard that reads this one is asking whether a patch
     * could land at all -- a class no rule mentions has nothing to attach to.
     * The two sets differ, so they are kept apart rather than merged.
     *
     * Built on first use and cached: it is a whole-index scan, and the guard
     * runs once per case.
     */
    const std::unordered_set<std::string> &RuleClasses() const;

    /*
     * (all requested permissions granted, the granted subset).
     *
     * Matches index.py:has_access, including the wildcard rule -- a matching
     * allow whose permission set is empty grants *everything* requested.
     */
    bool HasAccess(SymId src, SymId tgt, SymId cls, const std::vector<SymId> &perms,
                   std::vector<SymId> *granted) const;

    /*
     * has_access as if `allow <ruleSrc> <ruleTgt>:<ruleCls> { extra }` had been
     * appended to the policy -- VerifyAgent's "apply the patch on a copy and
     * re-query", without copying the index.
     *
     * index.py:load_text() *appends*, so the patched index is the union of the
     * existing rules and the patch; only the new rule is simulated here. An
     * empty *extra* is the wildcard rule Python parses out of `{ }`.
     *
     * *ruleApplies* says whether that rule's subject, target and class are the
     * ones being queried. It is not always true: the patch text renders an
     * absent field as the token `None`, and policy matching is string equality,
     * so a patch built from a denial with no scontext names a token that a
     * query carrying no scontext (Python's None) can never match. Assuming the
     * patch always applies would report a denied access as fixed.
     */
    bool HasAccessWithExtraAllow(SymId src, SymId tgt, SymId cls,
                                 const std::vector<SymId> &perms,
                                 const std::vector<SymId> &extra, bool ruleApplies,
                                 std::vector<SymId> *granted) const;

    /*
     * Best-effort ioctl verdict, with index.py:ioctl_allowed's precedence:
     * neverallowxperm rejects first, then a non-empty allowxperm whitelist wins
     * outright, and only when there is no whitelist does a plain
     * `allow ... ioctl` apply.
     */
    IoctlVerdict IoctlAllowed(SymId src, SymId tgt, SymId cls, SymId cmd) const;

    /*
     * IoctlAllowed as if `allowxperm src tgt:cls ioctl { extra }` had been
     * appended -- the allowxperm half of the same patch simulation. The
     * neverallowxperm check still runs first, exactly as in Python.
     */
    IoctlVerdict IoctlAllowedWithExtraXperm(SymId src, SymId tgt, SymId cls,
                                            SymId cmd,
                                            const std::vector<SymId> &extra,
                                            bool ruleApplies) const;

    /*
     * neverallow rules that *granting* *perms* would violate.
     *
     * A neverallow is a per-permission assertion: `neverallow A B:file execmod`
     * forbids execmod and says nothing about read. Matching it on the
     * (src, tgt, cls) triple alone reports the same red line for every request
     * on that triple -- measured on the upstream corpus, 2,646 of 2,700 such
     * "hits" named a permission the request never asked for, which suppressed
     * the repair path for 1,705 cases the very same query says are already
     * allowed. index.py:neverallow_rules carries the same fix.
     *
     * A rule whose permission list is empty is the `*` wildcard (the same
     * convention HasAccess uses) and matches every request. *perms* is a
     * parameter rather than an optional so that every caller states what it is
     * asking about; a default would silently restore the bug.
     */
    void NeverallowRules(SymId src, SymId tgt, SymId cls,
                         const std::vector<SymId> &perms,
                         std::vector<const PlRule *> *out) const;

    /*
     * Whether *ident* is a permission name the policy actually grants -- the
     * PLI's `@perm` set, whose ids come from the same intern table as a query's.
     * PlConverge's "the perm slot holds something that is not a permission"
     * guard needs it; a log line transcribed as `denied { 0x5413 }` with the
     * word `ioctl` written outside the braces would otherwise be read as a
     * request for a permission named 0x5413.
     */
    bool IsDeclaredPerm(SymId ident) const { return declaredPerms_.count(ident) != 0; }

    void AllowRules(SymId src, SymId tgt, SymId cls, std::vector<const PlRule *> *out) const;

    size_t ruleCount() const { return rules_.size(); }

    // Every loaded rule, used by converge to collect the object classes the
    // policy actually mentions (index.py:_known_tokens builds `classes` that
    // way, from rule classes rather than from a class list).
    const std::vector<PlRule> &rules() const { return rules_; }

private:
    PlIndex() = default;

    bool DecodeRule(const std::vector<std::string> &fields, size_t lineNo, std::string *err);
    bool SelfCheck(std::string *err) const;
    void RulesForClass(SymId cls, std::vector<const PlRule *> *out) const;
    bool Matches(const PlRule &rule, SymId ident, bool isSrc, const std::vector<SymId> &attrs) const;

    // Shared bodies of the plain and patch-simulating queries. `extra` is
    // nullptr for the plain query; otherwise it is the synthesized rule's
    // permission set (empty == wildcard, as in Python).
    bool HasAccessImpl(SymId src, SymId tgt, SymId cls, const std::vector<SymId> &perms,
                       const std::vector<SymId> *extra, bool extraApplies,
                       std::vector<SymId> *granted) const;
    IoctlVerdict IoctlAllowedImpl(SymId src, SymId tgt, SymId cls, SymId cmd,
                                  const std::vector<SymId> *extra, bool extraApplies) const;

    std::vector<std::string> syms_;
    std::unordered_map<std::string, SymId> symIndex_;

    std::vector<PlRule> rules_;
    std::unordered_map<SymId, std::vector<uint32_t>> rulesByClass_;

    std::unordered_map<SymId, std::vector<SymId>> attrs_;   // pre-expanded closure
    std::unordered_set<SymId> typeNames_;                   // keys of @type
    std::unordered_set<SymId> attrNames_;                   // @attr plus closure members
    std::unordered_set<SymId> known_;                       // @known
    std::unordered_set<SymId> classes_;                     // @class
    std::unordered_map<SymId, long long> declaredClassCounts_;
    std::unordered_set<SymId> declaredPerms_;

    // RuleClasses()'s cache. Mutable because the set is a pure function of
    // rules_, which do not change after load -- the query it answers is const.
    mutable std::unordered_set<std::string> ruleClasses_;
    mutable bool ruleClassesBuilt_ = false;

    IndexMeta meta_;
    std::string rev_;
    static const std::vector<SymId> kEmptyAttrs;
};

} // namespace policy_loop

#endif // POLICY_LOOP_PL_INDEX_H
