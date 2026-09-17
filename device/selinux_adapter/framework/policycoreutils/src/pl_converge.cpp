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

#include "pl_converge.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace policy_loop {

const char *const kCatAuto = "auto_repairable";
const char *const kCatHuman = "needs_human";
const char *const kCatNoise = "noise_or_already_allowed";
const char *const kCatUnclassified = "unclassified_no_policy";

namespace {

const char *const kDangerPatterns[] = {
    "chmod 777",
    "permissive;",
    "permissive ;",
    "setenforce 0",
    ":file *;",
    ":dir *;",
    "system_file:file *",
};

// Written into the report whenever a patch was produced; converge.py attaches
// the same sentence to any case that reaches the repair step.
const char *const kPatchTargetNote =
    "落点提示：请按 OpenHarmony sepolicy 组织把该规则放到所属子系统的 "
    "system/ 或 vendor/ 目录（跨组件类型定义放 public/），本工具不自动写盘。";

// The two classes converge.py treats as "a human must decide".
bool IsHumanClass(const std::string &c)
{
    return c == "POTENTIAL_ESCALATION" || c == "DOMAIN_OR_LABEL_MISMATCH";
}

// --------------------------------------------------------------------------
// Small helpers, each matching one Python expression it stands in for.
// --------------------------------------------------------------------------

void SortUniqueStr(std::vector<std::string> *v)
{
    std::sort(v->begin(), v->end());
    v->erase(std::unique(v->begin(), v->end()), v->end());
}

bool HasStr(const std::vector<std::string> &sortedVec, const std::string &s)
{
    return std::binary_search(sortedVec.begin(), sortedVec.end(), s);
}

// Set difference of two sorted-unique vectors; the result is sorted-unique and
// sits in `a`'s order, which is what `sorted(...)` yields in Python.
std::vector<std::string> StrDiff(const std::vector<std::string> &a,
                                 const std::vector<std::string> &bSorted)
{
    std::vector<std::string> out;
    for (const std::string &s : a) {
        if (!std::binary_search(bSorted.begin(), bSorted.end(), s)) {
            out.push_back(s);
        }
    }
    return out;
}

std::string JoinStr(const std::vector<std::string> &v, const char *sep)
{
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) {
            out += sep;
        }
        out += v[i];
    }
    return out;
}

bool IsAsciiSpace(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

// Python's str.split(): split on runs of whitespace, dropping empty fields.
std::vector<std::string> SplitWs(const std::string &s)
{
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && IsAsciiSpace(static_cast<unsigned char>(s[i]))) {
            ++i;
        }
        if (i >= s.size()) {
            break;
        }
        size_t start = i;
        while (i < s.size() && !IsAsciiSpace(static_cast<unsigned char>(s[i]))) {
            ++i;
        }
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

std::string StrStrip(const std::string &s)
{
    size_t b = 0;
    size_t e = s.size();
    while (b < e && IsAsciiSpace(static_cast<unsigned char>(s[b]))) {
        ++b;
    }
    while (e > b && IsAsciiSpace(static_cast<unsigned char>(s[e - 1]))) {
        --e;
    }
    return s.substr(b, e - b);
}

// `re.search(r"\{.*?\}", patch)` -- the first brace pair, lazily matched. Our
// patches are single-line, so the "dot does not cross a newline" subtlety of
// the Python pattern cannot bite.
bool FirstBracesInner(const std::string &s, std::string *out)
{
    size_t open = s.find('{');
    if (open == std::string::npos) {
        return false;
    }
    size_t close = s.find('}', open + 1);
    if (close == std::string::npos) {
        return false;
    }
    *out = s.substr(open + 1, close - open - 1);
    return true;
}

// Python's repr() of a str: single quotes, backslash escapes. Enough of the
// rule to be exact for policy tokens, which is all that can reach it.
std::string PyRepr(const std::string &s)
{
    std::string out = "'";
    char buf[8];
    for (unsigned char c : s) {
        if (c == '\\' || c == '\'') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else if (c < 0x20 || c == 0x7f) {
            std::snprintf(buf, sizeof(buf), "\\x%02x", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    out += "'";
    return out;
}

std::string PyListRepr(const std::vector<std::string> &v)
{
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += PyRepr(v[i]);
    }
    out += "]";
    return out;
}

/*
 * Truncate to *maxChars* *characters*, as Python string slicing does -- a
 * plain byte cut would split a UTF-8 sequence and, worse, would disagree with
 * the host on any log line carrying non-ASCII.
 *
 * Bytes that are not valid UTF-8 lead bytes count as one character each, which
 * is how Python's surrogateescape decodes them, so the two sides stay in step
 * on malformed input as well.
 */
std::string Utf8Truncate(const std::string &s, size_t maxChars)
{
    size_t chars = 0;
    size_t i = 0;
    while (i < s.size() && chars < maxChars) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = 1;
        if (c >= 0xF0) {
            len = 4;
        } else if (c >= 0xE0) {
            len = 3;
        } else if (c >= 0xC0) {
            len = 2;
        }
        if (i + len > s.size()) {
            len = 1;
        }
        i += len;
        ++chars;
    }
    return s.substr(0, i);
}

// converge.py _is_mls_level: ^s[0-9]+(\.c[0-9]+(-c[0-9]+)?)?$
bool IsMlsLevel(const std::string &s)
{
    size_t i = 0;
    if (i >= s.size() || s[i] != 's') {
        return false;
    }
    ++i;
    size_t digits = i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        ++i;
    }
    if (i == digits) {
        return false;
    }
    if (i == s.size()) {
        return true;
    }
    if (s[i] != '.') {
        return false;
    }
    ++i;
    if (i >= s.size() || s[i] != 'c') {
        return false;
    }
    ++i;
    digits = i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        ++i;
    }
    if (i == digits) {
        return false;
    }
    if (i == s.size()) {
        return true;
    }
    if (s[i] != '-') {
        return false;
    }
    ++i;
    if (i >= s.size() || s[i] != 'c') {
        return false;
    }
    ++i;
    digits = i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        ++i;
    }
    if (i == digits) {
        return false;
    }
    return i == s.size();
}

/*
 * index.py _ID_RE: [A-Za-z_][A-Za-z0-9_]* -- the shape a subject, target or
 * class token must have before _RULE_RE / _XP_RE will accept a patch line.
 */
bool IsIdentifier(const std::string &s)
{
    if (s.empty()) {
        return false;
    }
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        bool head = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
        bool tail = head || (c >= '0' && c <= '9');
        if (!(i == 0 ? head : tail)) {
            return false;
        }
    }
    return true;
}

// converge.py _patch_is_vacuous: a patch whose permission braces hold nothing.
bool PatchIsVacuous(const std::string &patch)
{
    std::string inner;
    if (!FirstBracesInner(patch, &inner)) {
        return false;               // unparseable -> don't over-block
    }
    return StrStrip(inner).empty();
}

bool IsServicePlaceholder(const std::string &s)
{
    return s == "default_service" || s == "default_hdf_service";
}

// Python str.isdigit(), ASCII subset -- the same test pl_avc_parser applies to
// `pid=`. Python's isdigit() also accepts non-ASCII digits, but a log-derived
// `service=` value is ASCII by construction, so the two agree on any corpus a
// device can produce.
bool IsAllDigits(const std::string &s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(),
                                     [](char c) { return c >= '0' && c <= '9'; });
}

// Python's `perms and perms <= {"add"}`: non-empty, and every element "add".
bool PermsAreOnlyAdd(const std::vector<std::string> &perms)
{
    return !perms.empty() && std::all_of(perms.begin(), perms.end(),
                                         [](const std::string &p) { return p == "add"; });
}

/*
 * policy/index.py::resolve_logical_target -- the M3 service mapping.
 *
 * A denial that went through the service manager logs a *placeholder* tcontext
 * (default_service for samgr, default_hdf_service for devmgr), but the rule
 * that would actually close the gap has to name the concrete type the
 * service= field stands for -- one of the sa_- or hdf_-prefixed types.
 *
 * Returns that concrete type, or "" when it cannot be resolved -- and
 * unresolvable must stay unresolved: a candidate is accepted only if this index
 * declares it, so the mapping can never invent a target.
 *
 * Two conservative, declaration-checked rules:
 *   named service   -> hdf_ + service (hdf_devmgr_class) / sa_ + service
 *   numeric service + samgr "add" -> sa_ + src
 * (an SA registers *itself* with samgr under its own id at startup, so the
 * concrete type is the SA type named after the subject). A numeric id naming a
 * *remote* SA (a client "get") is not resolvable without the external samgr
 * id-to-name registry, so the caller keeps the placeholder.
 */
std::string ResolveLogicalTarget(const PlIndex &index, const DenialRecord &rec)
{
    if (!rec.target_type.present || !IsServicePlaceholder(rec.target_type.value)) {
        return "";
    }
    if (!rec.service.present || rec.service.value.empty()) {
        return "";
    }
    const std::string cls = rec.tclass.present ? rec.tclass.value : "";
    if (cls != "samgr_class" && cls != "hdf_devmgr_class") {
        return "";
    }
    std::string cand;
    if (!IsAllDigits(rec.service.value)) {
        cand = std::string(cls == "hdf_devmgr_class" ? "hdf_" : "sa_") + rec.service.value;
    } else if (!rec.source_domain.present || rec.source_domain.value.empty()) {
        // Self-registration names the SA type after the *subject*: a record
        // whose scontext was malformed has no name to build one from.
        return "";
    } else if (cls == "samgr_class" && PermsAreOnlyAdd(rec.permissions)) {
        cand = "sa_" + rec.source_domain.value;
    } else {
        return "";
    }
    return index.IsDeclaredTypeOrAttr(cand) ? cand : "";
}

// --------------------------------------------------------------------------
// Verdict and pipeline
// --------------------------------------------------------------------------

struct PolicyVerdict {
    std::string src;
    std::string tgt;
    std::string cls;
    std::vector<std::string> requested;     // sorted, deduped
    std::vector<std::string> granted;       // sorted, deduped
    bool allAllowed = false;
    size_t neverallowHits = 0;
    bool hasIoctl = false;
    bool ioctlAllowed = false;
    std::string ioctlReason;
    std::string ioctlCmd;
};

SymId Lookup(const PlIndex &index, const OptStr &field)
{
    return field.present ? index.FindSym(field.value) : kNoSym;
}

/*
 * The requested permissions as ids, for the neverallow red-line check.
 *
 * Interned rather than looked up, exactly as BuildVerdict interns them for the
 * HasAccess query: a name the policy never mentions still has to get a stable
 * id so that it can be *compared* (and found not to overlap any rule's
 * permissions), rather than collapsing onto kNoSym and colliding with whatever
 * else landed there.
 */
std::vector<SymId> InternPerms(PlIndex &index, const std::vector<std::string> &perms)
{
    // Deliberately not sorted or de-duplicated: its only consumer is
    // NeverallowRules' overlap test, which scans the request linearly and is
    // indifferent to both. Canonicalising it would be work done for a reader
    // that does not exist.
    std::vector<SymId> ids;
    ids.reserve(perms.size());
    for (const std::string &p : perms) {
        ids.push_back(index.Intern(p));
    }
    return ids;
}

/*
 * converge.py's "the permission slot holds something that is not a permission"
 * guard: the requested permissions the policy never grants, in the order the
 * denial listed them (the order is part of the rendered reason, so it is not
 * sorted here).
 *
 * FindSym, not Intern: this is a question about the policy, and asking it must
 * not enlarge the intern table with the very token being questioned.
 */
std::vector<std::string> UndeclaredPerms(const PlIndex &index, const DenialRecord &rec)
{
    std::vector<std::string> bogus;
    for (const std::string &p : rec.permissions) {
        SymId id = index.FindSym(p);
        if (id == kNoSym || !index.IsDeclaredPerm(id)) {
            bogus.push_back(p);
        }
    }
    return bogus;
}

PolicyVerdict BuildVerdict(PlIndex &index, const DenialRecord &rec)
{
    PolicyVerdict v;
    // Python's PolicyAgent keeps the Optional: an absent field stays None, and
    // interpolating it into a patch string is what renders the literal token
    // `None` that the verify step then finds unmatchable. Rendering it here, at
    // the same place Python does, keeps that behaviour rather than inventing an
    // empty subject.
    v.src = rec.source_domain.present ? rec.source_domain.value : "None";
    v.tgt = rec.target_type.present ? rec.target_type.value : "None";
    v.cls = rec.tclass.present ? rec.tclass.value : "None";

    v.requested = rec.permissions;
    SortUniqueStr(&v.requested);

    // Requested permissions are interned rather than looked up, exactly as in
    // the query batch: a wildcard allow folds the requested names in verbatim,
    // including names the policy never mentions, and the host reports those
    // granted too.
    std::vector<SymId> reqIds;
    reqIds.reserve(v.requested.size());
    for (const std::string &p : v.requested) {
        reqIds.push_back(index.Intern(p));
    }

    SymId srcId = Lookup(index, rec.source_domain);
    // M3: a service-manager denial carries a placeholder tcontext, so querying
    // it verbatim asks whether the policy allows access to *the placeholder* --
    // it never does, and that answer reads as a real gap. Query the concrete
    // type `service=` stands for instead.
    //
    // Only the query symbol moves. v.tgt above stays the raw field, so the
    // patch text, the reviewer's neverallow re-check and the verify re-query
    // keep operating on what the log actually carried, and a placeholder that
    // resolves but is still denied keeps escalating exactly as before.
    const std::string resolvedTgt = ResolveLogicalTarget(index, rec);
    SymId tgtId = resolvedTgt.empty() ? Lookup(index, rec.target_type)
                                      : index.FindSym(resolvedTgt);
    SymId clsId = Lookup(index, rec.tclass);

    std::vector<SymId> grantedIds;
    v.allAllowed = index.HasAccess(srcId, tgtId, clsId, reqIds, &grantedIds);
    for (SymId id : grantedIds) {
        v.granted.push_back(index.symName(id));
    }
    SortUniqueStr(&v.granted);

    std::vector<const PlRule *> neverallow;
    index.NeverallowRules(srcId, tgtId, clsId, reqIds, &neverallow);
    v.neverallowHits = neverallow.size();

    if (HasStr(v.requested, "ioctl") && rec.ioctlCmd.present && !rec.ioctlCmd.value.empty()) {
        SymId cmd = index.FindSym(rec.ioctlCmd.value);
        IoctlVerdict ioctl = index.IoctlAllowed(srcId, tgtId, clsId, cmd);
        v.hasIoctl = true;
        v.ioctlAllowed = ioctl.allowed;
        v.ioctlReason = ioctl.reason;
        v.ioctlCmd = rec.ioctlCmd.value;
    }
    return v;
}

// security_agent.classify
std::string Classify(const PolicyVerdict &v, bool permissive)
{
    if (v.neverallowHits != 0) {
        return "POTENTIAL_ESCALATION";
    }
    if (v.hasIoctl && !v.ioctlAllowed) {
        return (v.ioctlReason == "allowxperm") ? "XPERM_GAP" : "MISSING_RULE";
    }
    if (v.allAllowed) {
        return permissive ? "NOISE_OR_ALREADY_FIXED" : "DOMAIN_OR_LABEL_MISMATCH";
    }
    return "MISSING_RULE";
}

struct QuickOutcome {
    bool hit = false;                       // false -> run the full pipeline
    std::string category;
    std::string classification;
    std::string why;
};

// converge.py _quick: the cases cheap enough to settle without a patch.
QuickOutcome Quick(const PolicyVerdict &v, bool permissive)
{
    QuickOutcome q;
    if (v.neverallowHits != 0) {
        q.hit = true;
        q.category = kCatHuman;
        q.classification = "POTENTIAL_ESCALATION";
        q.why = "命中 neverallow 红线：禁止自动放权（转人工）";
        return q;
    }
    if (!v.allAllowed) {
        return q;                       // genuinely missing -> needs a patch
    }
    if (v.hasIoctl && !v.ioctlAllowed) {
        return q;                       // xperm gap -> needs an allowxperm patch
    }
    q.hit = true;
    if (permissive) {
        q.category = kCatNoise;
        q.classification = "NOISE_OR_ALREADY_FIXED";
        q.why = "策略已允许（历史/噪声）";
    } else {
        q.category = kCatHuman;
        q.classification = "DOMAIN_OR_LABEL_MISMATCH";
        q.why = "策略已允许却被拒：疑似域/标签问题，非权限缺口";
    }
    return q;
}

struct PipelineOutcome {
    std::string category;
    std::string classification;
    std::string patch;
    std::string reviewStatus;
    std::string verifyStatus;
    std::string why;
    bool needsHuman = false;
    bool producedPatch = false;
};

/*
 * The closed form of SecurityAgent -> RepairAgent -> ReviewerAgent ->
 * VerifyAgent for one case.
 *
 * Only the fields converge.py reads back are computed: the recommendation's
 * title (which becomes `why`), the minimal patch, and the review/verify
 * statuses that decide the bucket. The agent traces, candidate lists and
 * explanations exist on the host for a human reading a single case; nothing
 * downstream of converge consumes them.
 */
PipelineOutcome RunPipeline(PlIndex &index, const DenialRecord &rec,
                            const PolicyVerdict &v, bool permissive)
{
    PipelineOutcome out;
    out.classification = Classify(v, permissive);

    // --- SecurityAgent: root cause + recommendation -----------------------
    std::string recTitle;
    if (out.classification == "POTENTIAL_ESCALATION") {
        out.needsHuman = true;
        recTitle = "人工确认/架构调整（禁止自动放权）";
    } else if (out.classification == "NOISE_OR_ALREADY_FIXED") {
        recTitle = "无需修复（噪声/已修复）";
    } else if (out.classification == "DOMAIN_OR_LABEL_MISMATCH") {
        out.needsHuman = true;
        recTitle = "检查域与标签（非权限问题）";
    } else {
        recTitle = "最小权限补齐";
    }

    // --- RepairAgent: candidate B is the only source of a patch -----------
    if (!out.needsHuman) {
        if (out.classification == "MISSING_RULE") {
            std::vector<std::string> missing = StrDiff(v.requested, v.granted);
            out.patch = "allow " + v.src + " " + v.tgt + ":" + v.cls +
                        " { " + JoinStr(missing, " ") + " };";
        } else if (out.classification == "XPERM_GAP") {
            out.patch = "allowxperm " + v.src + " " + v.tgt + ":" + v.cls +
                        " ioctl { " + v.ioctlCmd + " };";
        }
    }
    out.producedPatch = !out.patch.empty();

    // --- ReviewerAgent ----------------------------------------------------
    std::vector<std::string> reasons;
    if (out.patch.empty()) {
        out.reviewStatus = "SKIP";
    } else {
        for (const char *pat : kDangerPatterns) {
            if (out.patch.find(pat) != std::string::npos) {
                reasons.push_back("危险模式 " + PyRepr(pat));
            }
        }
        if (out.patch.find('*') != std::string::npos &&
            out.patch.find("allowxperm") == std::string::npos) {
            reasons.push_back("通配权限不可接受");
        }

        bool isXperm = out.patch.find("allowxperm") != std::string::npos;
        std::string inner;
        FirstBracesInner(out.patch, &inner);
        std::vector<std::string> patchPerms = SplitWs(inner);
        SortUniqueStr(&patchPerms);
        if (isXperm) {
            // The braces of an allowxperm hold ioctl COMMAND numbers, an xperm
            // whitelist, not permission names -- so they are measured against
            // the denial's ioctlcmd rather than against the requested perms.
            if (v.hasIoctl) {
                std::vector<std::string> onlyCmd{v.ioctlCmd};
                SortUniqueStr(&onlyCmd);
                std::vector<std::string> extra = StrDiff(patchPerms, onlyCmd);
                if (!v.ioctlCmd.empty() && !extra.empty()) {
                    reasons.push_back("allowxperm 白名单含非本 denial 的命令号 " + PyListRepr(extra));
                }
            }
        } else {
            std::vector<std::string> extra = StrDiff(patchPerms, v.requested);
            if (!patchPerms.empty() && !extra.empty()) {
                reasons.push_back("权限范围过大：多给了 " + PyListRepr(extra) + "，无 denial 证据支持");
            }
        }

        std::vector<const PlRule *> neverallow;
        index.NeverallowRules(Lookup(index, rec.source_domain),
                              Lookup(index, rec.target_type),
                              Lookup(index, rec.tclass),
                              InternPerms(index, v.requested), &neverallow);
        if (!neverallow.empty()) {
            reasons.push_back("与 neverallow 冲突：" + neverallow[0]->raw.substr(0, 120));
        }
        out.reviewStatus = reasons.empty() ? "APPROVE" : "REJECT";
    }

    // --- VerifyAgent: patch applied on a simulated copy, then re-queried ---
    if (out.patch.empty()) {
        out.verifyStatus = out.needsHuman ? "HUMAN_REVIEW_REQUIRED" : "VERIFIED_AS_NOISE";
    } else if (out.reviewStatus != "APPROVE") {
        out.verifyStatus = "BLOCKED_BY_REVIEW";
    } else {
        // VerifyAgent re-parses the patch, so the re-query has to be phrased in
        // the patch's own terms. Two consequences of that, both reproduced:
        //
        //  - A denial that carried no scontext renders the literal token `None`,
        //    whose query side is Python's None -- not the string -- and so can
        //    never match. A patch against an unidentifiable subject comes back
        //    unverified rather than fixed.
        //  - The tokens are *interned*, not merely looked up: a present token
        //    the policy has never seen still has to match the patch rule that
        //    spells it out, which a never-adding lookup cannot express. For a
        //    token the policy does know this is the same id FindSym returns.
        SymId srcId = rec.source_domain.present ? index.Intern(rec.source_domain.value) : kNoSym;
        SymId tgtId = rec.target_type.present ? index.Intern(rec.target_type.value) : kNoSym;
        SymId clsId = rec.tclass.present ? index.Intern(rec.tclass.value) : kNoSym;

        std::vector<const PlRule *> neverallow;
        index.NeverallowRules(srcId, tgtId, clsId,
                              InternPerms(index, v.requested), &neverallow);
        if (!neverallow.empty()) {
            out.verifyStatus = "SECURITY_REGRESSION";
        } else {
            std::string inner;
            FirstBracesInner(out.patch, &inner);
            std::vector<std::string> patchInner = SplitWs(inner);
            SortUniqueStr(&patchInner);
            std::vector<SymId> extraIds;
            extraIds.reserve(patchInner.size());
            for (const std::string &p : patchInner) {
                extraIds.push_back(index.Intern(p));
            }

            std::vector<SymId> reqIds;
            reqIds.reserve(v.requested.size());
            for (const std::string &p : v.requested) {
                reqIds.push_back(index.Intern(p));
            }

            // The patch only becomes a rule if the patch line parses: index.py
            // _feed_line falls through to `skipped_count += 1` when neither
            // _XP_RE nor _RULE_RE matches, so a class token like
            // `binderpermissive=1` is dropped and the re-query fails. _ID_RE is
            // that grammar's identifier rule, and an absent field renders the
            // identifier `None` -- which still cannot match, because the query
            // side of an absent field is Python's None rather than a string.
            bool ruleApplies = rec.source_domain.present && rec.target_type.present &&
                               rec.tclass.present && IsIdentifier(v.src) && IsIdentifier(v.tgt) &&
                               IsIdentifier(v.cls);

            bool allOk = false;
            if (out.patch.find("allowxperm") != std::string::npos) {
                // The patch's xperm brace holds this denial's command number as
                // text; intern it so the same string compares equal.
                SymId cmd = v.ioctlCmd.empty() ? kNoSym : index.Intern(v.ioctlCmd);
                IoctlVerdict ioctl = index.IoctlAllowedWithExtraXperm(
                    srcId, tgtId, clsId, cmd, extraIds, ruleApplies);
                allOk = ioctl.allowed;
            } else {
                std::vector<SymId> granted;
                allOk = index.HasAccessWithExtraAllow(srcId, tgtId, clsId, reqIds, extraIds,
                                                      ruleApplies, &granted);
            }
            out.verifyStatus = allOk ? "SUCCESS" : "FAILED";
        }
    }

    // converge.py: (case.recommended or {}).get("title") or case.classification
    out.why = recTitle.empty() ? out.classification : recTitle;
    out.category = kCatUnclassified;
    return out;
}

// converge.py _categorize
std::string Categorize(const PipelineOutcome &out)
{
    if (IsHumanClass(out.classification) || out.needsHuman) {
        return kCatHuman;
    }
    if (out.classification == "NOISE_OR_ALREADY_FIXED") {
        return kCatNoise;
    }
    if (!out.patch.empty()) {
        if (out.reviewStatus == "APPROVE" && out.verifyStatus == "SUCCESS") {
            return kCatAuto;
        }
        return kCatHuman;               // patch rejected / not verified
    }
    if (out.classification == "MISSING_RULE") {
        return kCatHuman;               // repair produced nothing -> not safe
    }
    return kCatNoise;
}

void Bump(CountedList *list, const std::string &key)
{
    for (auto &entry : *list) {
        if (entry.first == key) {
            ++entry.second;
            return;
        }
    }
    list->push_back({key, 1});
}

long long LookupCount(const CountedList &list, const std::string &key)
{
    for (const auto &entry : list) {
        if (entry.first == key) {
            return entry.second;
        }
    }
    return 0;
}

} // namespace

CaseVerdict ExplainCase(const DenialRecord &rec, PlIndex *index, CasePath path)
{
    CaseVerdict out;

    if (index == nullptr) {
        // converge.py's "no policy" mode: the record is mirrored back and
        // nothing is decided. Rendered the same way BuildVerdict renders it so
        // a caller sees one spelling of an absent field, index or not.
        out.src = rec.source_domain.present ? rec.source_domain.value : "None";
        out.tgt = rec.target_type.present ? rec.target_type.value : "None";
        out.cls = rec.tclass.present ? rec.tclass.value : "None";
        out.requested = rec.permissions;
        SortUniqueStr(&out.requested);
        out.category = kCatUnclassified;
        return out;
    }

    const bool permissive = (rec.permissive == Permissive::kPermissive);
    PolicyVerdict v = BuildVerdict(*index, rec);

    out.src = v.src;
    out.tgt = v.tgt;
    out.cls = v.cls;
    out.requested = v.requested;
    out.granted = v.granted;
    out.missing = StrDiff(v.requested, v.granted);
    out.allAllowed = v.allAllowed;
    out.neverallowHits = v.neverallowHits;
    out.hasIoctl = v.hasIoctl;
    out.ioctlAllowed = v.ioctlAllowed;
    out.ioctlReason = v.ioctlReason;
    out.ioctlCmd = v.ioctlCmd;

    if (path == CasePath::kQuickThenPipeline) {
        QuickOutcome quick = Quick(v, permissive);
        if (quick.hit) {
            // Settled without the pipeline -- and the pipeline must not be run
            // anyway: for these cases it would answer `why` differently (the
            // recommendation title rather than the quick reason), which is the
            // wording the batch report carries.
            out.quickSettled = true;
            out.category = quick.category;
            out.classification = quick.classification;
            out.why = quick.why;
            return out;
        }
    }

    PipelineOutcome out2 = RunPipeline(*index, rec, v, permissive);
    out.classification = out2.classification;
    out.patch = out2.patch;
    out.reviewStatus = out2.reviewStatus;
    out.verifyStatus = out2.verifyStatus;
    out.why = out2.why;
    out.needsHuman = out2.needsHuman;
    out.producedPatch = out2.producedPatch;
    out.category = Categorize(out2);
    return out;
}

void ApplyGuards(const DenialRecord &rec, PlIndex *index, CaseVerdict *verdict)
{
    if (verdict == nullptr) {
        return;
    }
    verdict->guardsApplied = true;
    if (index == nullptr || verdict->category != kCatAuto) {
        // Nothing to guard. Either there is no policy to check the tokens
        // against, or the case is not one the pipeline offered to repair --
        // and `autoSafe` stays false for both, because neither is auto-safe.
        return;
    }

    const OptStr &tgtField = rec.target_type;
    const OptStr &srcField = rec.source_domain;
    const OptStr &clsField = rec.tclass;
    bool tgtTruthy = tgtField.present && !tgtField.value.empty();
    auto isKnownToken = [index](const OptStr &field) {
        if (!field.present) {
            return false;
        }
        SymId id = index->FindSym(field.value);     // never interns: a query
        return id != kNoSym && index->IsKnownToken(id);
    };
    bool srcKnown = isKnownToken(srcField);
    bool tgtKnown = isKnownToken(tgtField);
    bool clsKnown = clsField.present && index->RuleClasses().count(clsField.value) != 0;

    // The first guard to fire decides, so the order below is the ranking of the
    // reasons: a target that is a security level is reported as that rather than
    // as the unknown token it also is.
    std::string why;
    std::vector<std::string> bogusPerms;
    if (tgtTruthy && IsMlsLevel(tgtField.value)) {
        why = "目标上下文可疑（被解析成安全级别而非类型，"
              "多为日志/注释笔误，勿照抄规则）";
    } else if (tgtTruthy && IsServicePlaceholder(tgtField.value)) {
        why = "目标为 default_* 占位符（service 需映射到具体 "
              "sa_*/hdf 类型才能落规则），转人工";
    } else if (!srcKnown || !tgtKnown) {
        // The message names whichever side was missing, rendering an
        // absent field the way Python's f-string does: as None.
        const OptStr &unknown = srcKnown ? tgtField : srcField;
        std::string name = unknown.present ? unknown.value : "None";
        why = "主体/目标「" + name + "」不在当前策略语料中"
              "（设备新增域、生成的数字 service 标签或标注异常），"
              "补丁无法落点验证，转人工";
    } else if (!clsKnown) {
        std::string name = clsField.present ? clsField.value : "None";
        why = "对象类「" + name + "」不在策略任何规则中出现"
              "（疑为日志笔误），补丁无法落点验证，转人工";
    } else if (!(bogusPerms = UndeclaredPerms(*index, rec)).empty()) {
        // The same argument as the class guard, one level down: a patch naming
        // a permission the policy never grants is not a policy that fails to
        // help, it is one the compiler rejects. The corpus really does carry
        // `denied { 0x5413 }` with the word `ioctl` written *outside* the
        // braces, so this fires on a corrupt log line -- and saying so is the
        // useful answer, not a patch that cannot compile.
        why = "权限位含非权限名「" + JoinStr(bogusPerms, "、") + "」"
              "（策略里没有任何规则授予过它；疑为日志转写笔误——"
              "ioctl 命令号被写进了权限位，而 `ioctl` 被写在括号外），"
              "照抄会落到编译不过的规则上，转人工";
    } else if (PatchIsVacuous(verdict->patch)) {
        why = "补丁为空权限（ioctl 类缺口需 allowxperm 语义，"
              "当前修复路径给不出有效最小补丁），转人工";
    }

    if (why.empty()) {
        verdict->autoSafe = true;
        return;
    }
    verdict->category = kCatHuman;
    verdict->advisory = why;
    // `why` is the answer, and for a downgraded case the answer is the reason it
    // must not be applied. Leaving the pipeline's sentence there instead would
    // word this case differently from the report that carries it -- `advisory`
    // is what preserves the distinction, by saying which part of the answer the
    // guards contributed.
    verdict->why = why;
}

ConvergeReport Converge(const std::vector<DenialRecord> &records, PlIndex *index)
{
    ConvergeReport report;
    report.totalDenials = static_cast<long long>(records.size());

    // Group by fingerprint, preserving first-appearance order -- the cluster
    // order is visible in the report, so it is part of the parity contract.
    std::vector<Cluster> clusters;
    std::unordered_map<std::string, size_t> byFp;
    std::vector<std::vector<const DenialRecord *>> groups;

    for (const DenialRecord &rec : records) {
        std::string fp = Fingerprint(rec);
        auto it = byFp.find(fp);
        if (it == byFp.end()) {
            byFp[fp] = groups.size();
            groups.push_back({});
            it = byFp.find(fp);
        }
        groups[it->second].push_back(&rec);
    }

    /*
     * converge.py:_known_tokens -- the tokens a patch may be placed against --
     * now lives on the guards (see ApplyGuards), which is the only thing that
     * reads it. It is a question about a single case, so it belongs with the
     * single-case decision rather than with the batch that happens to call it.
     *
     * The index answers it: `@known` for the types, and RuleClasses() for the
     * classes rules mention. The latter is not IsKnownClass -- the exporter's
     * `@class` list is a different set -- and it is cached on the index rather
     * than rebuilt per case.
     */
    std::unordered_map<std::string, long long> patchCases;
    std::unordered_map<std::string, long long> patchDenials;
    std::vector<std::string> patchOrder;

    for (const std::vector<const DenialRecord *> &group : groups) {
        const DenialRecord &first = *group[0];

        Cluster cl;
        cl.fp = Fingerprint(first);
        cl.count = static_cast<long long>(group.size());
        cl.src = first.source_domain.present ? first.source_domain.value : "";
        cl.tgt = first.target_type.present ? first.target_type.value : "";
        cl.cls = first.tclass.present ? first.tclass.value : "";
        cl.perms = first.permissions;
        cl.ioctl = first.ioctlCmd.present ? first.ioctlCmd.value : "";
        cl.sampleRaw = first.raw;

        for (const DenialRecord *r : group) {
            if (r->permissive == Permissive::kPermissive) {
                ++cl.permissive;
            } else if (r->permissive == Permissive::kEnforcing) {
                ++cl.enforcing;
            } else {
                ++cl.permissiveUnknown;
            }
            const OptStr &comm = r->comm;
            if (comm.present && !comm.value.empty() && cl.comms.size() < 5 &&
                std::find(cl.comms.begin(), cl.comms.end(), comm.value) == cl.comms.end()) {
                cl.comms.push_back(comm.value);
            }
        }

        if (index != nullptr) {
            // The same two calls the tool's per-record mode makes, in the same
            // order. A cluster is decided by its first record, which is why the
            // batch and per-record answers cannot disagree.
            CaseVerdict verdict = ExplainCase(first, index, CasePath::kQuickThenPipeline);
            // Never auto-suggest a degenerate patch. Applying the guards is a
            // separate step from reaching the verdict -- they answer whether the
            // patch may be applied unattended, not what it is -- and they write
            // their reason into `why` when they downgrade a case.
            ApplyGuards(first, index, &verdict);

            cl.category = verdict.category;
            cl.classification = verdict.classification;
            cl.why = verdict.why;
            // Empty on the quick path, exactly as before: those two branches
            // used to leave these fields at their defaults.
            cl.patch = verdict.patch;
            cl.reviewStatus = verdict.reviewStatus;
            cl.verifyStatus = verdict.verifyStatus;
            if (report.targetNote.empty() && verdict.producedPatch) {
                report.targetNote = kPatchTargetNote;
            }
        }

        if (cl.category == kCatAuto && !cl.patch.empty()) {
            if (patchCases.find(cl.patch) == patchCases.end()) {
                patchOrder.push_back(cl.patch);
            }
            patchCases[cl.patch] += 1;
            patchDenials[cl.patch] += cl.count;
        } else if (cl.category == kCatHuman) {
            HumanItem item;
            item.caseId = cl.fp;
            item.count = cl.count;
            item.src = cl.src;
            item.tgt = cl.tgt;
            item.cls = cl.cls;
            // sorted(), not deduped: converge.py reports the permission list in
            // the order the log gave it, repeats and all.
            item.perms = cl.perms;
            std::sort(item.perms.begin(), item.perms.end());
            item.classification = cl.classification;
            item.review = cl.reviewStatus;
            item.verify = cl.verifyStatus;
            item.why = cl.why;
            item.sample = Utf8Truncate(cl.sampleRaw, 200);
            report.humanItems.push_back(item);
        }

        clusters.push_back(cl);
    }

    report.uniqueCases = static_cast<long long>(clusters.size());
    for (const Cluster &cl : clusters) {
        Bump(&report.byCategory, cl.category);
        if (cl.category != kCatUnclassified) {
            Bump(&report.byClassification,
                 cl.classification.empty() ? "n/a" : cl.classification);
        }
    }
    report.clusters = clusters;

    std::sort(patchOrder.begin(), patchOrder.end());
    report.autoPatchLines = patchOrder;
    for (const std::string &patch : patchOrder) {
        PatchStat stat;
        stat.cases = patchCases[patch];
        stat.denials = patchDenials[patch];
        report.autoPatchStats.push_back({patch, stat});
    }
    report.noiseCases = LookupCount(report.byCategory, kCatNoise);
    return report;
}

// --------------------------------------------------------------------------
// JSON
// --------------------------------------------------------------------------

namespace {

void AppendJsonString(std::string *out, const std::string &s)
{
    *out += JsonString(s);
}

void AppendStringArray(std::string *out, const std::vector<std::string> &v)
{
    *out += "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) {
            *out += ", ";
        }
        AppendJsonString(out, v[i]);
    }
    *out += "]";
}

void AppendCountedList(std::string *out, const CountedList &list)
{
    *out += "{";
    for (size_t i = 0; i < list.size(); ++i) {
        if (i != 0) {
            *out += ", ";
        }
        AppendJsonString(out, list[i].first);
        *out += ": " + std::to_string(list[i].second);
    }
    *out += "}";
}

void AppendCluster(std::string *out, const Cluster &cl)
{
    *out += "{\"fp\": ";
    AppendJsonString(out, cl.fp);
    *out += ", \"count\": " + std::to_string(cl.count);
    *out += ", \"permissive\": " + std::to_string(cl.permissive);
    *out += ", \"enforcing\": " + std::to_string(cl.enforcing);
    *out += ", \"permissive_unknown\": " + std::to_string(cl.permissiveUnknown);
    *out += ", \"src\": ";
    AppendJsonString(out, cl.src);
    *out += ", \"tgt\": ";
    AppendJsonString(out, cl.tgt);
    *out += ", \"cls\": ";
    AppendJsonString(out, cl.cls);
    *out += ", \"perms\": ";
    AppendStringArray(out, cl.perms);
    *out += ", \"ioctl\": ";
    AppendJsonString(out, cl.ioctl);
    *out += ", \"comms\": ";
    AppendStringArray(out, cl.comms);
    *out += ", \"sample_raw\": ";
    AppendJsonString(out, cl.sampleRaw);
    *out += ", \"category\": ";
    AppendJsonString(out, cl.category);
    *out += ", \"classification\": ";
    AppendJsonString(out, cl.classification);
    *out += ", \"patch\": ";
    AppendJsonString(out, cl.patch);
    *out += ", \"review_status\": ";
    AppendJsonString(out, cl.reviewStatus);
    *out += ", \"verify_status\": ";
    AppendJsonString(out, cl.verifyStatus);
    *out += ", \"why\": ";
    AppendJsonString(out, cl.why);
    *out += "}";
}

void AppendHumanItem(std::string *out, const HumanItem &item)
{
    *out += "{\"case\": ";
    AppendJsonString(out, item.caseId);
    *out += ", \"count\": " + std::to_string(item.count);
    *out += ", \"src\": ";
    AppendJsonString(out, item.src);
    *out += ", \"tgt\": ";
    AppendJsonString(out, item.tgt);
    *out += ", \"cls\": ";
    AppendJsonString(out, item.cls);
    *out += ", \"perms\": ";
    AppendStringArray(out, item.perms);
    *out += ", \"classification\": ";
    AppendJsonString(out, item.classification);
    *out += ", \"review\": ";
    AppendJsonString(out, item.review);
    *out += ", \"verify\": ";
    AppendJsonString(out, item.verify);
    *out += ", \"why\": ";
    AppendJsonString(out, item.why);
    *out += ", \"sample\": ";
    AppendJsonString(out, item.sample);
    *out += "}";
}

// Python's `round(x, 2)` rendered the way json.dumps would: two decimals, then
// trimmed to the shortest form that still reads as a float ("2.0", not "2.00").
std::string Round2(double value)
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.2f", value);
    std::string s = buf;
    if (s.find('.') != std::string::npos) {
        size_t last = s.find_last_not_of('0');
        if (last != std::string::npos && s[last] == '.') {
            ++last;                     // keep one digit after the point
        }
        s = s.substr(0, last + 1);
    }
    return s;
}

std::string ReadinessNote(const ConvergeReport &report)
{
    long long autoCnt = LookupCount(report.byCategory, kCatAuto);
    long long humanCnt = LookupCount(report.byCategory, kCatHuman);
    long long noiseCnt = LookupCount(report.byCategory, kCatNoise);
    long long unclass = LookupCount(report.byCategory, kCatUnclassified);
    if (unclass == report.uniqueCases) {
        return "未提供策略索引：只能去重统计，不能生成修复建议。"
               "加 --policy 指向 sepolicy 目录或 .te 文件即可出收敛方案。";
    }
    long long denom = report.uniqueCases > 1 ? report.uniqueCases : 1;
    // Python's round() with no ndigits: to nearest, ties to even. nearbyint
    // under the default rounding mode is the same rule on the same value.
    long long humanPct = static_cast<long long>(
        std::nearbyint(100.0 * static_cast<double>(humanCnt) / static_cast<double>(denom)));
    return "日志 " + std::to_string(report.totalDenials) + " 条 → 去重后 " +
           std::to_string(report.uniqueCases) + " 个唯一案例" +
           "（噪声/已允许 " + std::to_string(noiseCnt) + "）。其中 " +
           std::to_string(autoCnt) + " 类可自动出最小权限补丁、" +
           std::to_string(humanCnt) + " 类需人工决策（占唯一案例约 " +
           std::to_string(humanPct) + "%）。"
           "只建议，不写盘；真机上 enforcing 回归验证留待 L4。";
}

} // namespace

std::string ReportToJson(const ConvergeReport &report)
{
    std::string out;
    out.reserve(4096 + report.clusters.size() * 512);

    out += "{\"total_denials\": " + std::to_string(report.totalDenials);
    out += ", \"unique_cases\": " + std::to_string(report.uniqueCases);
    out += ", \"by_category\": ";
    AppendCountedList(&out, report.byCategory);
    out += ", \"by_classification\": ";
    AppendCountedList(&out, report.byClassification);

    out += ", \"clusters\": [";
    for (size_t i = 0; i < report.clusters.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        AppendCluster(&out, report.clusters[i]);
    }
    out += "]";

    out += ", \"auto_patch_lines\": ";
    AppendStringArray(&out, report.autoPatchLines);

    out += ", \"auto_patch_stats\": {";
    for (size_t i = 0; i < report.autoPatchStats.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        AppendJsonString(&out, report.autoPatchStats[i].first);
        out += ": {\"cases\": " + std::to_string(report.autoPatchStats[i].second.cases) +
               ", \"denials\": " + std::to_string(report.autoPatchStats[i].second.denials) + "}";
    }
    out += "}";

    out += ", \"human_items\": [";
    for (size_t i = 0; i < report.humanItems.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        AppendHumanItem(&out, report.humanItems[i]);
    }
    out += "]";

    out += ", \"noise_cases\": " + std::to_string(report.noiseCases);
    out += ", \"target_note\": ";
    AppendJsonString(&out, report.targetNote);
    out += ", \"dedup_ratio\": ";
    if (report.uniqueCases == 0) {
        out += "0.0";
    } else {
        out += Round2(static_cast<double>(report.totalDenials) /
                      static_cast<double>(report.uniqueCases));
    }
    out += ", \"readiness_note\": ";
    AppendJsonString(&out, ReadinessNote(report));
    out += "}\n";
    return out;
}

// security_agent._HUMAN -- the five templates, verbatim.
//
// Converge never read these back, which is why they were left in Python until
// the tool grew a single-denial mode. Byte-for-byte parity with the host
// wording is the acceptance criterion for the same reason the rest of the
// pipeline has one: a developer reading the device's answer and a reviewer
// reading the host's must not be told two different things. The text is copied
// rather than paraphrased, and tests/diff_device.py -- not this comment -- is
// what proves it stayed equal.
std::string ExplainHuman(const std::string &classification,
                         const std::string &src, const std::string &tgt,
                         const std::string &cls,
                         const std::vector<std::string> &requested,
                         const std::vector<std::string> &granted,
                         const std::string &ioctlCmd)
{
    // Python: ", ".join(sorted(set(requested) - set(granted))) or cls
    std::vector<std::string> missing;
    for (const std::string &p : requested) {
        if (std::find(granted.begin(), granted.end(), p) == granted.end()) {
            missing.push_back(p);
        }
    }
    SortUniqueStr(&missing);
    std::string missingStr = missing.empty() ? cls : JoinStr(missing, ", ");
    std::string permsStr = JoinStr(requested, ", ");

    if (classification == "MISSING_RULE") {
        return "安全策略缺少允许规则：" + src + " 访问 " + tgt + ":" + cls +
               " 的 {" + missingStr + "} 权限，当前策略未授予。需要确认该访问"
               "是否合理后，按最小权限补齐缺失权限。";
    }
    if (classification == "XPERM_GAP") {
        return src + " 对 " + tgt + ":" + cls + " 的 ioctl(" + ioctlCmd +
               ") 被拒：策略已允许 ioctl 大类，但该命令号不在 allowxperm "
               "白名单内，属于「细粒度权限缺口」而非「完全没有权限」。";
    }
    if (classification == "POTENTIAL_ESCALATION") {
        return "该访问命中 neverallow 红线：" + src + " 请求 " + tgt + ":" +
               cls + " {" + permsStr + "}。即使技术上可加规则，也极可能是越权"
               "或架构问题，PolicyLoop 拒绝自动放权。";
    }
    if (classification == "NOISE_OR_ALREADY_FIXED") {
        return "当前策略已允许该访问（denial 仍出现且处于 permissive），多为"
               "历史日志或噪声/已修复记录，不建议新增权限。";
    }
    if (classification == "DOMAIN_OR_LABEL_MISMATCH") {
        return "策略已允许但 enforcing 下仍被拒：疑似进程域或对象标签与实际"
               "不符，应检查 type_transition / file_contexts 等，而非加权限。";
    }
    return "";
}

// The tool's `--explain`: one denial line in, the answer the batch report would
// have given that case out.
//
// The verdict is taken down the full-pipeline path rather than behind Converge's
// `Quick` shortcut. Quick exists to avoid work in a batch, and it can only ever
// skip cases whose classification it already knows -- POTENTIAL_ESCALATION and
// the two already-allowed ones -- for which Classify returns the identical
// string. So going the long way costs one case's work and buys the fields Quick
// does not compute at all: the patch, the reviewer's and verifier's verdicts on
// it, and (above all) the explanation, which only the agent path produces.
//
// One field deliberately differs from the batch report for those same skipped
// cases: `why`. Batch writes Quick's own wording there ("策略已允许（历史/噪声）")
// because it never ran the agent; here it is the agent's recommendation title,
// which is what Python's single-case path reports. Same class, two true
// sentences -- not a drift to reconcile.
ExplainResult ExplainDenial(const std::string &line, PlIndex *index)
{
    ExplainResult r;
    if (index == nullptr) {
        return r;
    }
    std::vector<DenialRecord> records = ParseDenials(line);
    if (records.empty()) {
        return r;
    }
    const DenialRecord &rec = records[0];
    r.parsed = true;

    CaseVerdict v = ExplainCase(rec, index, CasePath::kFullPipeline);

    r.src = v.src;
    r.tgt = v.tgt;
    r.cls = v.cls;
    r.requested = v.requested;
    r.granted = v.granted;
    r.missing = v.missing;
    r.ioctlCmd = v.ioctlCmd;

    r.classification = v.classification;
    r.explanation = ExplainHuman(v.classification, v.src, v.tgt, v.cls,
                                 v.requested, v.granted, v.ioctlCmd);

    // security_agent's recommendation id -- the half of `recommended` that the
    // pipeline does not carry, since only its title survives into `why`.
    if (v.classification == "POTENTIAL_ESCALATION" ||
        v.classification == "DOMAIN_OR_LABEL_MISMATCH") {
        r.recommendedId = "C";
    } else if (v.classification == "NOISE_OR_ALREADY_FIXED") {
        r.recommendedId = "-";
    } else {
        r.recommendedId = "B";
    }
    r.recommendedTitle = v.why;
    r.needsHuman = v.needsHuman;
    r.patch = v.patch;
    r.reviewStatus = v.reviewStatus;
    r.verifyStatus = v.verifyStatus;
    return r;
}

// The same object the host's single-case path emits, byte for byte, so the two
// can be compared with `diff`. The key order below is sorted, which is what
// `json.dumps(..., sort_keys=True)` produces; it is part of the contract rather
// than a style choice, because the comparison is textual.
std::string ExplainToJson(const ExplainResult &r)
{
    std::string out;
    out.reserve(1024);
    out += "{\"classification\": ";
    AppendJsonString(&out, r.classification);
    out += ", \"cls\": ";
    AppendJsonString(&out, r.cls);
    out += ", \"explanation\": ";
    AppendJsonString(&out, r.explanation);
    out += ", \"granted\": ";
    AppendStringArray(&out, r.granted);
    // Absent and empty collapse to the same null: a denial either carried an
    // ioctl command number or it did not, and BuildVerdict records both as an
    // empty string, so there is nothing left to tell apart here.
    out += ", \"ioctl\": ";
    if (r.ioctlCmd.empty()) {
        out += "null";
    } else {
        AppendJsonString(&out, r.ioctlCmd);
    }
    out += ", \"missing\": ";
    AppendStringArray(&out, r.missing);
    out += ", \"needs_human\": ";
    out += r.needsHuman ? "true" : "false";
    out += ", \"patch\": ";
    AppendJsonString(&out, r.patch);
    out += ", \"recommended\": {\"id\": ";
    AppendJsonString(&out, r.recommendedId);
    out += ", \"title\": ";
    AppendJsonString(&out, r.recommendedTitle);
    out += "}";
    out += ", \"requested\": ";
    AppendStringArray(&out, r.requested);
    out += ", \"review\": ";
    AppendJsonString(&out, r.reviewStatus);
    out += ", \"src\": ";
    AppendJsonString(&out, r.src);
    out += ", \"tgt\": ";
    AppendJsonString(&out, r.tgt);
    out += ", \"verify\": ";
    AppendJsonString(&out, r.verifyStatus);
    out += "}\n";
    return out;
}

// CaseVerdict as JSON, one object, keys sorted, trailing newline -- the same
// shape contract ReportToJson and ExplainToJson follow, so a host driver can
// compare a per-record answer against its own with `diff`.
//
// Every field is emitted, including the ones the settle path did not compute:
// a consumer reading `patch` needs `quick_settled` beside it to know whether
// the empty string means "no patch proposed" or "the pipeline never ran". The
// flag is the difference, and dropping the empty fields instead would erase it.
std::string CaseVerdictToJson(const CaseVerdict &v)
{
    std::string out;
    out.reserve(512);
    out += "{\"advisory\": ";
    AppendJsonString(&out, v.advisory);
    out += ", \"all_allowed\": ";
    out += v.allAllowed ? "true" : "false";
    out += ", \"auto_safe\": ";
    out += v.autoSafe ? "true" : "false";
    out += ", \"category\": ";
    AppendJsonString(&out, v.category);
    out += ", \"classification\": ";
    AppendJsonString(&out, v.classification);
    out += ", \"cls\": ";
    AppendJsonString(&out, v.cls);
    out += ", \"granted\": ";
    AppendStringArray(&out, v.granted);
    out += ", \"guards_applied\": ";
    out += v.guardsApplied ? "true" : "false";
    out += ", \"has_ioctl\": ";
    out += v.hasIoctl ? "true" : "false";
    out += ", \"ioctl_allowed\": ";
    out += v.ioctlAllowed ? "true" : "false";
    // Empty means the denial carried no command number, so it renders as null
    // for the same reason ExplainToJson's does.
    out += ", \"ioctl_cmd\": ";
    if (v.ioctlCmd.empty()) {
        out += "null";
    } else {
        AppendJsonString(&out, v.ioctlCmd);
    }
    out += ", \"ioctl_reason\": ";
    AppendJsonString(&out, v.ioctlReason);
    out += ", \"missing\": ";
    AppendStringArray(&out, v.missing);
    out += ", \"needs_human\": ";
    out += v.needsHuman ? "true" : "false";
    out += ", \"neverallow_hits\": ";
    out += std::to_string(v.neverallowHits);
    out += ", \"patch\": ";
    AppendJsonString(&out, v.patch);
    out += ", \"produced_patch\": ";
    out += v.producedPatch ? "true" : "false";
    out += ", \"quick_settled\": ";
    out += v.quickSettled ? "true" : "false";
    out += ", \"requested\": ";
    AppendStringArray(&out, v.requested);
    out += ", \"review_status\": ";
    AppendJsonString(&out, v.reviewStatus);
    out += ", \"src\": ";
    AppendJsonString(&out, v.src);
    out += ", \"tgt\": ";
    AppendJsonString(&out, v.tgt);
    out += ", \"verify_status\": ";
    AppendJsonString(&out, v.verifyStatus);
    out += ", \"why\": ";
    AppendJsonString(&out, v.why);
    out += "}\n";
    return out;
}

} // namespace policy_loop
