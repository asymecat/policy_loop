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

/*
 * One `sehap_contexts` entry: the APL <-> domain bridge (policy/sehap.py).
 *
 * An OpenHarmony application does not choose its own SELinux domain -- the
 * platform derives it from the APL in the signing profile, plus a `debuggable`
 * flag -- so a denial carrying `scontext=u:r:normal_hap` says "some normal-APL
 * app", naming neither the app nor the layer that owns the fix. No `.te` file
 * states that mapping; `sehap_contexts` does. The PLI carries it because the
 * device ships no sepolicy *source* to read it from.
 *
 * `source` (the file the host read the entry from) is deliberately not in the
 * PLI: it is a build-machine path, and no answer this table is asked for
 * depends on it.
 *
 * Seven fields, `-` for an absent one. The table does not collapse a domain to
 * one level: `isolated_gpu` legitimately appears at three APLs and
 * `distributed_isolate_hap` appears twice (plain and debuggable), so a domain
 * maps to a *set* of entries and a "dedupe by domain" would silently narrow
 * the answer.
 */
struct PlHapEntry {
    std::string apl;
    std::string domain;
    std::string type;
    bool debuggable = false;
    std::string name;
    std::string extension;
    std::string extra;
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
    // The APL bridge. Counters, not mere decoration: a truncated payload that
    // loses `@hap` lines changes what the cross-layer answers say, so these are
    // self-checked the same way the rule counters are. `hapSkipped` is the
    // exception -- it counts source lines the *host* indexer rejected, which is
    // not derivable from the PLI, so it is reported rather than checked.
    long long hapEntries = 0;
    long long hapDomains = 0;
    long long hapNames = 0;
    long long hapApls = 0;
    long long hapDebuggable = 0;
    long long hapSkipped = 0;
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
     * The APL bridge (see PlHapEntry), in file order.
     *
     * Kept in file order on purpose: the order is what the host's `SehapTable`
     * reports its entries in, and the cross-layer view prints them. Nothing
     * here sorts or dedupes them -- a domain legitimately has several.
     */
    const std::vector<PlHapEntry> &hapEntries() const { return hap_; }

    // The entries declaring *domain*, as indices into hapEntries(), in file
    // order. Empty when the domain declares none -- which is itself the answer
    // to "is this an application process at all", so it is a query, not an
    // error.
    const std::vector<uint32_t> &HapForDomain(const std::string &domain) const;

    // Distinct domains the table declares, ascending. Python's
    // SehapTable.domains() -- the enumeration "who *else* could do this" walks.
    const std::vector<std::string> &HapDomains() const;
    // Distinct APL levels across the whole table, ascending (SehapTable.apls_all).
    const std::vector<std::string> &HapAplsAll() const;

    /*
     * Is *domain* an application domain? Mirrors SehapTable.is_app_domain,
     * empty string included: the host spells it `bool(domain) and domain in
     * by_domain`, so an absent scontext (rendered as "") is never an app.
     */
    bool IsAppDomain(const std::string &domain) const
    {
        return !domain.empty() && hapByDomain_.count(domain) != 0;
    }

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
    bool DecodeHap(const std::string &body, size_t lineNo, std::string *err);
    bool SelfCheck(std::string *err) const;
    void RulesForClass(SymId cls, std::vector<const PlRule *> *out) const;
    bool Matches(const PlRule &rule, SymId ident, bool isSrc, const std::vector<SymId> &attrs) const;

    /*
     * Rule indices that could match *ident* on one side of an access, ascending
     * by rule index and deduped.
     *
     * A superset filter, never a verdict -- the caller still runs Matches on
     * every candidate. The narrowing is sound because Matches can only return
     * true when the rule's positive set holds the identifier or an attribute it
     * inherits, or the side is `*` (which carries no token at all); so those
     * are exactly the rules worth trying. An extra candidate costs one
     * comparison, a *missing* one would silently drop an authorization, so the
     * postings are built to over-include rather than to be exact. Negatives are
     * deliberately not indexed: they reject inside Matches, and pruning a rule
     * for naming one would be wrong, since a negative excludes an identifier
     * and its attributes while the rule may still admit it by other members.
     *
     * This replaces a scan of every rule of the object class -- 7,400 of them
     * for `file` on the rk3568 tree, against a measured median of 1 surviving
     * candidate over the upstream corpus.
     */
    void Candidates(RuleKind kind, bool isSrc, SymId cls, SymId ident,
                    const std::vector<SymId> &attrs, std::vector<uint32_t> *out) const;

    // Fills postings_. Called once, at the end of loading: rules_ never changes
    // afterwards (a patch is simulated through the *extra* parameters rather
    // than by appending), so unlike the host engine there is no stale tail to
    // re-scan and no reason to rebuild.
    void BuildCandidates();

    struct Postings {
        std::vector<uint32_t> star;     // rule sides written `*`, indexed by nothing
        std::unordered_map<SymId, std::vector<uint32_t>> byToken;
    };

    // (kind, side, class) packed into one key: kind is a uint8_t, and SymId is
    // 32 bits, so the whole thing fits a uint64_t without collision.
    static uint64_t SideKey(RuleKind kind, bool isSrc, SymId cls)
    {
        return (static_cast<uint64_t>(kind) << 33) |
               (static_cast<uint64_t>(isSrc ? 1u : 0u) << 32) |
               static_cast<uint64_t>(cls);
    }

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

    // Query narrowing, keyed by SideKey(). Built once by BuildCandidates().
    std::unordered_map<uint64_t, Postings> postings_;

    std::unordered_map<SymId, std::vector<SymId>> attrs_;   // pre-expanded closure
    std::unordered_set<SymId> typeNames_;                   // keys of @type
    std::unordered_set<SymId> attrNames_;                   // @attr plus closure members
    std::unordered_set<SymId> known_;                       // @known
    std::unordered_set<SymId> classes_;                     // @class
    std::unordered_map<SymId, long long> declaredClassCounts_;
    std::unordered_set<SymId> declaredPerms_;

    // The APL bridge. `hapByDomain_` holds indices into `hap_`, which is never
    // reordered after loading, so the indices stay valid.
    std::vector<PlHapEntry> hap_;
    std::unordered_map<std::string, std::vector<uint32_t>> hapByDomain_;
    // Both derived from hap_ once, on first use (the queries that read them run
    // per application domain, not per entry).
    mutable std::vector<std::string> hapDomains_;
    mutable std::vector<std::string> hapApls_;
    mutable bool hapViewsBuilt_ = false;
    void BuildHapViews() const;

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
