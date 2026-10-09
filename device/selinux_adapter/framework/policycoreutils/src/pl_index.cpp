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

#include "pl_index.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "pl_sha1.h"

namespace policy_loop {

const std::vector<SymId> PlIndex::kEmptyAttrs;

namespace {

const long long kPliVersion = 2;

std::vector<std::string> SplitWhitespace(const std::string &s)
{
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
            ++i;
        }
        if (i >= s.size()) {
            break;
        }
        size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n') {
            ++i;
        }
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

std::vector<std::string> SplitChar(const std::string &s, char sep)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t pos = s.find(sep, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
}

bool StartsWith(const std::string &s, const char *prefix)
{
    return s.compare(0, std::strlen(prefix), prefix) == 0;
}

bool ParseLongLong(const std::string &s, long long *out)
{
    if (s.empty()) {
        return false;
    }
    errno = 0;
    char *end = nullptr;
    long long v = std::strtoll(s.c_str(), &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0') {
        return false;
    }
    *out = v;
    return true;
}

} // namespace

// --------------------------------------------------------------------------
// Symbols
// --------------------------------------------------------------------------

SymId PlIndex::FindSym(const std::string &name) const
{
    auto it = symIndex_.find(name);
    return (it == symIndex_.end()) ? kNoSym : it->second;
}

SymId PlIndex::Intern(const std::string &name)
{
    auto it = symIndex_.find(name);
    if (it != symIndex_.end()) {
        return it->second;
    }
    SymId id = static_cast<SymId>(syms_.size());
    syms_.push_back(name);
    symIndex_.emplace(name, id);
    return id;
}

const std::vector<SymId> &PlIndex::Attrs(SymId ident) const
{
    auto it = attrs_.find(ident);
    return (it == attrs_.end()) ? kEmptyAttrs : it->second;
}

bool PlIndex::IsDeclaredTypeOrAttr(const std::string &name) const
{
    SymId id = FindSym(name);
    if (id == kNoSym) {
        return false;
    }
    return typeNames_.count(id) != 0 || attrNames_.count(id) != 0;
}

const std::unordered_set<std::string> &PlIndex::RuleClasses() const
{
    if (!ruleClassesBuilt_) {
        for (const PlRule &rule : rules_) {
            ruleClasses_.insert(syms_[rule.cls]);
        }
        ruleClassesBuilt_ = true;
    }
    return ruleClasses_;
}

// --------------------------------------------------------------------------
// Loading
// --------------------------------------------------------------------------

namespace {

// Decodes one side of a rule line: `*` is the star flag, `-name` a negative
// member, `-` the empty-side marker, anything else a positive member.
void DecodeSubject(const std::string &field, std::vector<SymId> *pos, std::vector<SymId> *neg,
                   bool *star, PlIndex *index)
{
    if (field == "-") {
        return;
    }
    for (const std::string &tok : SplitChar(field, ',')) {
        if (tok.empty()) {
            continue;
        }
        if (tok == "*") {
            *star = true;
        } else if (tok[0] == '-') {
            neg->push_back(index->Intern(tok.substr(1)));
        } else {
            pos->push_back(index->Intern(tok));
        }
    }
}

void SortUnique(std::vector<SymId> *v)
{
    std::sort(v->begin(), v->end());
    v->erase(std::unique(v->begin(), v->end()), v->end());
}

} // namespace

/*
 * One `@hap` line: seven positional fields, `-` for an absent one.
 *
 * Strict on purpose, mirroring pli.py:_dec_hap. `debuggable` is only ever `0`
 * or `1` -- anything else means a corrupted line, and inventing a value for it
 * would produce a table that quietly disagrees with the host about which
 * entries are debug builds. The field count is exact for the same reason: a
 * short line is a truncated payload, not a table with fewer columns.
 */
bool PlIndex::DecodeHap(const std::string &body, size_t lineNo, std::string *err)
{
    std::vector<std::string> f = SplitWhitespace(body);
    if (f.size() != 7) {
        *err = "line " + std::to_string(lineNo) + ": @hap expects 7 fields, got " +
               std::to_string(f.size());
        return false;
    }
    if (f[3] != "0" && f[3] != "1") {
        *err = "line " + std::to_string(lineNo) + ": malformed @hap debuggable flag: '" +
               f[3] + "'";
        return false;
    }
    auto field = [&f](size_t i) { return f[i] == "-" ? std::string() : f[i]; };
    PlHapEntry entry;
    entry.apl = field(0);
    entry.domain = field(1);
    entry.type = field(2);
    entry.debuggable = (f[3] == "1");
    entry.name = field(4);
    entry.extension = field(5);
    entry.extra = field(6);
    // A domain-less entry is kept rather than rejected: the host's reader keeps
    // it too (pli.py:_dec_hap does not check), and dropping it here would make
    // the two loaders disagree about `hap_entries` -- the counter that exists
    // to catch exactly this kind of divergence.
    hap_.push_back(entry);
    return true;
}

void PlIndex::BuildHapViews() const
{
    if (hapViewsBuilt_) {
        return;
    }
    std::unordered_set<std::string> domains;
    std::unordered_set<std::string> apls;
    for (const PlHapEntry &e : hap_) {
        domains.insert(e.domain);
        apls.insert(e.apl);
    }
    // std::string's ordering is byte-wise over char, which for the ASCII names
    // in sehap_contexts is the same order Python's sorted() produces.
    hapDomains_.assign(domains.begin(), domains.end());
    hapApls_.assign(apls.begin(), apls.end());
    std::sort(hapDomains_.begin(), hapDomains_.end());
    std::sort(hapApls_.begin(), hapApls_.end());
    hapViewsBuilt_ = true;
}

const std::vector<uint32_t> &PlIndex::HapForDomain(const std::string &domain) const
{
    static const std::vector<uint32_t> kEmpty;
    auto it = hapByDomain_.find(domain);
    return (it == hapByDomain_.end()) ? kEmpty : it->second;
}

const std::vector<std::string> &PlIndex::HapDomains() const
{
    BuildHapViews();
    return hapDomains_;
}

const std::vector<std::string> &PlIndex::HapAplsAll() const
{
    BuildHapViews();
    return hapApls_;
}

bool PlIndex::DecodeRule(const std::vector<std::string> &fields, size_t lineNo, std::string *err)
{
    PlRule rule;
    const std::string &letter = fields[0];
    if (letter == "a") {
        rule.kind = RuleKind::kAllow;
    } else if (letter == "n") {
        rule.kind = RuleKind::kNeverAllow;
    } else if (letter == "x") {
        rule.kind = RuleKind::kAllowXperm;
    } else if (letter == "z") {
        rule.kind = RuleKind::kNeverAllowXperm;
    } else {
        *err = "line " + std::to_string(lineNo) + ": unknown rule kind '" + letter + "'";
        return false;
    }

    rule.cls = Intern(fields[1]);
    DecodeSubject(fields[2], &rule.src, &rule.srcNeg, &rule.srcStar, this);
    DecodeSubject(fields[3], &rule.tgt, &rule.tgtNeg, &rule.tgtStar, this);
    SortUnique(&rule.src);
    SortUnique(&rule.srcNeg);
    SortUnique(&rule.tgt);
    SortUnique(&rule.tgtNeg);

    const std::string &permsField = fields[4];
    if (IsXperm(rule.kind)) {
        std::string body = permsField;
        if (!body.empty() && body[0] == '~') {
            rule.xpermInvert = true;
            body = body.substr(1);
        }
        size_t colon = body.find(':');
        if (colon == std::string::npos) {
            *err = "line " + std::to_string(lineNo) + ": xperm field has no ':' separator";
            return false;
        }
        std::string perm = body.substr(0, colon);
        rule.xpermPerm = perm.empty() ? kNoSym : Intern(perm);
        for (const std::string &cmd : SplitChar(body.substr(colon + 1), ',')) {
            if (!cmd.empty()) {
                rule.xperms.push_back(Intern(cmd));
            }
        }
        SortUnique(&rule.xperms);
    } else if (permsField == "*") {
        // An empty permission set is a wildcard in has_access; the encoding
        // distinguishes it from "no permissions at all" and must stay empty.
    } else {
        for (const std::string &perm : SplitChar(permsField, ',')) {
            if (!perm.empty()) {
                rule.perms.push_back(Intern(perm));
            }
        }
        SortUnique(&rule.perms);
    }

    rule.raw = fields[0];
    for (size_t i = 1; i < fields.size(); ++i) {
        rule.raw += " " + fields[i];
    }
    rules_.push_back(rule);
    return true;
}

std::unique_ptr<PlIndex> PlIndex::LoadFromText(const std::string &text, std::string *err)
{
    std::unique_ptr<PlIndex> index(new PlIndex());
    index->rev_ = Sha1Hex(text).substr(0, 12);
    std::vector<std::string> lines = SplitChar(text, '\n');
    // SplitChar always yields at least one element; a trailing newline makes the
    // last one empty, which the loop below simply skips.
    if (lines.empty() || lines[0] != "PLI1") {
        *err = "not a PLI1 file";
        return nullptr;
    }
    if (lines.size() < 2 || lines[1] != "@rev " + std::to_string(kPliVersion)) {
        *err = "unsupported PLI revision: " +
               (lines.size() < 2 ? std::string("<missing>") : lines[1]);
        return nullptr;
    }

    std::unordered_map<std::string, long long> metaFields;
    long long expectedRules = -1;
    size_t bodyStart = lines.size();
    std::vector<std::string> unknownSections;

    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string &line = lines[i];
        if (line.empty()) {
            continue;
        }
        if (StartsWith(line, "@meta ")) {
            for (const std::string &field : SplitWhitespace(line.substr(6))) {
                size_t eq = field.find('=');
                if (eq == std::string::npos) {
                    *err = "@meta field without '=': " + field;
                    return nullptr;
                }
                long long value = 0;
                if (!ParseLongLong(field.substr(eq + 1), &value)) {
                    *err = "malformed @meta value: " + field;
                    return nullptr;
                }
                metaFields[field.substr(0, eq)] = value;
            }
        } else if (StartsWith(line, "@src ")) {
            index->meta_.source = line.substr(5);
        } else if (StartsWith(line, "@class ")) {
            std::vector<std::string> f = SplitWhitespace(line.substr(7));
            if (f.size() != 2) {
                *err = "malformed @class line: " + line;
                return nullptr;
            }
            long long count = 0;
            if (!ParseLongLong(f[1], &count)) {
                *err = "malformed @class count: " + line;
                return nullptr;
            }
            SymId id = index->Intern(f[0]);
            index->declaredClassCounts_[id] = count;
            index->classes_.insert(id);
        } else if (StartsWith(line, "@type ")) {
            std::vector<std::string> f = SplitWhitespace(line.substr(6));
            if (f.empty()) {
                *err = "malformed @type line: " + line;
                return nullptr;
            }
            SymId id = index->Intern(f[0]);
            index->typeNames_.insert(id);
            std::vector<SymId> closure;
            for (size_t k = 1; k < f.size(); ++k) {
                SymId attr = index->Intern(f[k]);
                index->attrNames_.insert(attr);
                closure.push_back(attr);
            }
            SortUnique(&closure);
            index->attrs_[id] = std::move(closure);
        } else if (StartsWith(line, "@attr ")) {
            index->attrNames_.insert(index->Intern(line.substr(6)));
        } else if (StartsWith(line, "@known ")) {
            index->known_.insert(index->Intern(line.substr(7)));
        } else if (StartsWith(line, "@perm ")) {
            index->declaredPerms_.insert(index->Intern(line.substr(6)));
        } else if (StartsWith(line, "@hap ")) {
            if (!index->DecodeHap(line.substr(5), i + 1, err)) {
                return nullptr;
            }
        } else if (StartsWith(line, "@rev ")) {
            // Validated before the loop; listed so the catch-all below, which
            // must stay last, does not report it as an unknown section.
        } else if (StartsWith(line, "@rules ")) {
            if (!ParseLongLong(line.substr(7), &expectedRules)) {
                *err = "malformed @rules header: " + line;
                return nullptr;
            }
            bodyStart = i + 1;
            break;
        } else if (StartsWith(line, "@")) {
            // A section this reader does not know. Skipping it is the only
            // forward-compatible thing to do, but skipping it *silently* means
            // an index built by a newer exporter loads fine and then answers
            // wrong, which is worse than refusing it. Collect the names and say
            // so after the header is parsed.
            const std::string name = line.substr(1, line.find(' ') - 1);
            if (std::find(unknownSections.begin(), unknownSections.end(), name) ==
                unknownSections.end()) {
                unknownSections.push_back(name);
            }
        }
    }

    if (expectedRules < 0) {
        *err = "missing @rules header";
        return nullptr;
    }

    if (!unknownSections.empty()) {
        std::string names;
        for (size_t i = 0; i < unknownSections.size(); ++i) {
            names += (i == 0 ? "" : ", ") + unknownSections[i];
        }
        fprintf(stderr,
                "denial_check: warning: index carries section(s) this reader "
                "does not understand: %s -- they were ignored, so any answer "
                "that depends on them (HAP/APL mapping) is wrong.\n",
                names.c_str());
    }

    for (size_t i = bodyStart; i < lines.size(); ++i) {
        if (lines[i].empty()) {
            continue;
        }
        std::vector<std::string> fields = SplitWhitespace(lines[i]);
        if (fields.size() != 5) {
            *err = "line " + std::to_string(i + 1) + ": expected 5 fields, got " +
                   std::to_string(fields.size());
            return nullptr;
        }
        if (!index->DecodeRule(fields, i + 1, err)) {
            return nullptr;
        }
    }

    // Group by class once, preserving rule order within a class so that
    // "first matching rule" answers stay identical to the Python engine's.
    for (uint32_t i = 0; i < index->rules_.size(); ++i) {
        index->rulesByClass_[index->rules_[i].cls].push_back(i);
    }
    index->BuildCandidates();

    // Same for the APL bridge: entries stay in file order inside a domain, and
    // the indices into hap_ are what the dedupe-free `lookup_domain` returns.
    for (uint32_t i = 0; i < index->hap_.size(); ++i) {
        index->hapByDomain_[index->hap_[i].domain].push_back(i);
    }

    // Reported rather than checked: `skipped` counts macro statements the host
    // indexer could not expand, which is not derivable from the PLI payload.
    auto metaGet = [&metaFields](const char *key) -> long long {
        auto it = metaFields.find(key);
        return (it == metaFields.end()) ? -1 : it->second;
    };
    index->meta_.rules = metaGet("rules");
    index->meta_.allow = metaGet("allow");
    index->meta_.neverallow = metaGet("neverallow");
    index->meta_.allowxperm = metaGet("allowxperm");
    index->meta_.neverallowxperm = metaGet("neverallowxperm");
    index->meta_.types = metaGet("types");
    index->meta_.attrs = metaGet("attrs");
    index->meta_.classes = metaGet("classes");
    index->meta_.perms = metaGet("perms");
    index->meta_.known = metaGet("known");
    index->meta_.skipped = metaGet("skipped");
    index->meta_.hapEntries = metaGet("hap_entries");
    index->meta_.hapDomains = metaGet("hap_domains");
    index->meta_.hapNames = metaGet("hap_names");
    index->meta_.hapApls = metaGet("hap_apls");
    index->meta_.hapDebuggable = metaGet("hap_debuggable");
    index->meta_.hapSkipped = metaGet("hap_skipped");

    if (!index->SelfCheck(err)) {
        return nullptr;
    }
    return index;
}

bool PlIndex::SelfCheck(std::string *err) const
{
    // *what* is a `@meta` key and *from* names the lines it should have been
    // derived from, so a mismatch points at the section that is short rather
    // than at "the rules" for a counter that has nothing to do with them.
    auto fail = [err](const std::string &what, const char *from, long long want,
                      long long got) {
        *err = "PLI self-check failed: " + what + " declares " + std::to_string(want) +
               " but the " + from + " lines give " + std::to_string(got) +
               " (truncated or corrupted index?)";
        return false;
    };

    long long counts[4] = {0, 0, 0, 0};
    std::unordered_map<SymId, long long> classCounts;
    std::unordered_set<SymId> permSet;
    std::unordered_set<SymId> tokenSet;
    for (const PlRule &rule : rules_) {
        switch (rule.kind) {
            case RuleKind::kAllow: ++counts[0]; break;
            case RuleKind::kNeverAllow: ++counts[1]; break;
            case RuleKind::kAllowXperm: ++counts[2]; break;
            case RuleKind::kNeverAllowXperm: ++counts[3]; break;
        }
        ++classCounts[rule.cls];
        if (!IsXperm(rule.kind)) {
            permSet.insert(rule.perms.begin(), rule.perms.end());
        }
        tokenSet.insert(rule.src.begin(), rule.src.end());
        tokenSet.insert(rule.tgt.begin(), rule.tgt.end());
    }
    tokenSet.insert(typeNames_.begin(), typeNames_.end());

    if (meta_.rules >= 0 && meta_.rules != static_cast<long long>(rules_.size())) {
        return fail("rules", "rule", meta_.rules, static_cast<long long>(rules_.size()));
    }
    const long long *declared[4] = {&meta_.allow, &meta_.neverallow, &meta_.allowxperm,
                                    &meta_.neverallowxperm};
    const char *names[4] = {"allow", "neverallow", "allowxperm", "neverallowxperm"};
    for (int i = 0; i < 4; ++i) {
        if (*declared[i] >= 0 && *declared[i] != counts[i]) {
            return fail(names[i], "rule", *declared[i], counts[i]);
        }
    }
    if (meta_.types >= 0 && meta_.types != static_cast<long long>(typeNames_.size())) {
        return fail("types", "@type", meta_.types, static_cast<long long>(typeNames_.size()));
    }
    if (meta_.attrs >= 0 && meta_.attrs != static_cast<long long>(attrNames_.size())) {
        return fail("attrs", "@attr", meta_.attrs, static_cast<long long>(attrNames_.size()));
    }
    if (meta_.classes >= 0 && meta_.classes != static_cast<long long>(classes_.size())) {
        return fail("classes", "@class", meta_.classes, static_cast<long long>(classes_.size()));
    }
    if (meta_.perms >= 0 && meta_.perms != static_cast<long long>(permSet.size())) {
        return fail("perms", "@perm", meta_.perms, static_cast<long long>(permSet.size()));
    }
    if (meta_.known >= 0 && meta_.known != static_cast<long long>(known_.size())) {
        return fail("known", "@known", meta_.known, static_cast<long long>(known_.size()));
    }
    // The three declared *sets* are checked as sets, not merely by size, so a
    // corrupt file that drops one token while duplicating another still fails.
    // Python's reader makes the same three comparisons.
    if (known_ != tokenSet) {
        *err = "PLI self-check failed: @known disagrees with the tokens the rule "
               "lines imply (" + std::to_string(known_.size()) + " declared, " +
               std::to_string(tokenSet.size()) + " implied)";
        return false;
    }
    if (declaredPerms_ != permSet) {
        *err = "PLI self-check failed: @perm disagrees with the permissions the "
               "rule lines imply (" + std::to_string(declaredPerms_.size()) +
               " declared, " + std::to_string(permSet.size()) + " implied)";
        return false;
    }
    if (declaredClassCounts_ != classCounts) {
        *err = "PLI self-check failed: @class counts disagree with the rule lines";
        return false;
    }

    // The APL bridge, on the same terms as the rule counters -- and for the
    // reason the format has counters at all: a payload truncated in transfer
    // would otherwise load fine and answer cross-layer questions from a
    // partial table. `hap_skipped` is exempt, like `skipped`: it counts source
    // lines the host indexer rejected, which the PLI does not carry.
    if (meta_.hapEntries >= 0 &&
        meta_.hapEntries != static_cast<long long>(hap_.size())) {
        return fail("hap_entries", "@hap", meta_.hapEntries, static_cast<long long>(hap_.size()));
    }
    BuildHapViews();
    long long debuggable = 0;
    for (const PlHapEntry &e : hap_) {
        if (e.debuggable) {
            ++debuggable;
        }
    }
    // `by_name` on the host holds only the *named* entries, so an entry with an
    // absent name contributes nothing here either.
    std::unordered_set<std::string> hapNames;
    for (const PlHapEntry &e : hap_) {
        if (!e.name.empty()) {
            hapNames.insert(e.name);
        }
    }
    if (meta_.hapDomains >= 0 &&
        meta_.hapDomains != static_cast<long long>(hapDomains_.size())) {
        return fail("hap_domains", "@hap", meta_.hapDomains,
                    static_cast<long long>(hapDomains_.size()));
    }
    if (meta_.hapNames >= 0 &&
        meta_.hapNames != static_cast<long long>(hapNames.size())) {
        return fail("hap_names", "@hap", meta_.hapNames,
                    static_cast<long long>(hapNames.size()));
    }
    if (meta_.hapApls >= 0 &&
        meta_.hapApls != static_cast<long long>(hapApls_.size())) {
        return fail("hap_apls", "@hap", meta_.hapApls, static_cast<long long>(hapApls_.size()));
    }
    if (meta_.hapDebuggable >= 0 && meta_.hapDebuggable != debuggable) {
        return fail("hap_debuggable", "@hap", meta_.hapDebuggable, debuggable);
    }
    return true;
}

namespace {

bool ReadWholeFile(const std::string &path, std::string *out, std::string *err)
{
    FILE *fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        *err = path + ": " + std::strerror(errno);
        return false;
    }
    char buf[65536];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) {
        out->append(buf, n);
    }
    bool ok = !std::ferror(fp);
    if (!ok) {
        *err = path + ": read error";
    }
    std::fclose(fp);
    return ok;
}

} // namespace

std::unique_ptr<PlIndex> PlIndex::LoadFile(const std::string &path, std::string *err)
{
    std::string text;
    if (!ReadWholeFile(path, &text, err)) {
        return nullptr;
    }
    return LoadFromText(text, err);
}

// --------------------------------------------------------------------------
// Queries
// --------------------------------------------------------------------------

namespace {

// Both vectors ascending and deduped (Candidates guarantees it); keep only the
// members of *a that b also holds.
void IntersectSorted(std::vector<uint32_t> *a, const std::vector<uint32_t> &b)
{
    size_t w = 0;
    for (uint32_t v : *a) {
        if (std::binary_search(b.begin(), b.end(), v)) {
            (*a)[w++] = v;
        }
    }
    a->resize(w);
}

// Union of two ascending, deduped vectors, left ascending. The candidate sets
// are tiny (median 1, p90 3 over the corpus), so re-sorting beats a merge.
void MergeSorted(std::vector<uint32_t> *a, const std::vector<uint32_t> &b)
{
    a->insert(a->end(), b.begin(), b.end());
    std::sort(a->begin(), a->end());
    a->erase(std::unique(a->begin(), a->end()), a->end());
}

} // namespace

void PlIndex::RulesForClass(SymId cls, std::vector<const PlRule *> *out) const
{
    out->clear();
    auto it = rulesByClass_.find(cls);
    if (it == rulesByClass_.end()) {
        return;
    }
    for (uint32_t idx : it->second) {
        out->push_back(&rules_[idx]);
    }
}

void PlIndex::BuildCandidates()
{
    postings_.clear();
    for (uint32_t i = 0; i < rules_.size(); ++i) {
        const PlRule &r = rules_[i];
        for (int side = 0; side < 2; ++side) {
            const bool isSrc = (side == 0);
            const std::vector<SymId> &pos = isSrc ? r.src : r.tgt;
            const bool star = isSrc ? r.srcStar : r.tgtStar;
            Postings &p = postings_[SideKey(r.kind, isSrc, r.cls)];
            if (star) {
                // No token to file it under, so it is a candidate for every
                // query on this (kind, side, class) -- which is correct: a `*`
                // side matches whatever is asked.
                p.star.push_back(i);
            }
            for (SymId tok : pos) {
                p.byToken[tok].push_back(i);
            }
        }
    }
}

void PlIndex::Candidates(RuleKind kind, bool isSrc, SymId cls, SymId ident,
                         const std::vector<SymId> &attrs, std::vector<uint32_t> *out) const
{
    out->clear();
    auto it = postings_.find(SideKey(kind, isSrc, cls));
    if (it == postings_.end()) {
        return;
    }
    const Postings &p = it->second;
    out->insert(out->end(), p.star.begin(), p.star.end());
    auto add = [&](SymId tok) {
        auto f = p.byToken.find(tok);
        if (f != p.byToken.end()) {
            out->insert(out->end(), f->second.begin(), f->second.end());
        }
    };
    // The identifier itself *and* every attribute it inherits: Matches accepts
    // either, so both have to be able to nominate a rule.
    if (ident != kNoSym) {
        add(ident);
    }
    for (SymId attr : attrs) {
        add(attr);
    }
    // Ascending and deduped, because callers that report "the first matching
    // rule" must keep the answer a full scan would have given.
    std::sort(out->begin(), out->end());
    out->erase(std::unique(out->begin(), out->end()), out->end());
}

bool PlIndex::Matches(const PlRule &rule, SymId ident, bool isSrc,
                      const std::vector<SymId> &attrs) const
{
    const std::vector<SymId> &pos = isSrc ? rule.src : rule.tgt;
    const std::vector<SymId> &neg = isSrc ? rule.srcNeg : rule.tgtNeg;
    bool star = isSrc ? rule.srcStar : rule.tgtStar;

    // A negative member excludes the identifier itself or any attribute it
    // inherits; it is checked before the positive side, so it wins.
    if (std::binary_search(neg.begin(), neg.end(), ident)) {
        return false;
    }
    for (SymId attr : attrs) {
        if (std::binary_search(neg.begin(), neg.end(), attr)) {
            return false;
        }
    }
    if (star || std::binary_search(pos.begin(), pos.end(), ident)) {
        return true;
    }
    for (SymId attr : attrs) {
        if (std::binary_search(pos.begin(), pos.end(), attr)) {
            return true;
        }
    }
    return false;
}

void PlIndex::AllowRules(SymId src, SymId tgt, SymId cls, std::vector<const PlRule *> *out) const
{
    out->clear();
    const std::vector<SymId> &aSrc = Attrs(src);
    const std::vector<SymId> &aTgt = Attrs(tgt);
    std::vector<uint32_t> candidates, side;
    Candidates(RuleKind::kAllow, true, cls, src, aSrc, &candidates);
    Candidates(RuleKind::kAllow, false, cls, tgt, aTgt, &side);
    IntersectSorted(&candidates, side);
    for (uint32_t idx : candidates) {
        const PlRule *rule = &rules_[idx];
        if (!Matches(*rule, src, true, aSrc) || !Matches(*rule, tgt, false, aTgt)) {
            continue;
        }
        out->push_back(rule);
    }
}

void PlIndex::NeverallowRules(SymId src, SymId tgt, SymId cls,
                              const std::vector<SymId> &perms,
                              std::vector<const PlRule *> *out) const
{
    out->clear();
    const std::vector<SymId> &aSrc = Attrs(src);
    const std::vector<SymId> &aTgt = Attrs(tgt);
    std::vector<uint32_t> candidates, side;
    Candidates(RuleKind::kNeverAllow, true, cls, src, aSrc, &candidates);
    Candidates(RuleKind::kNeverAllow, false, cls, tgt, aTgt, &side);
    IntersectSorted(&candidates, side);
    for (uint32_t idx : candidates) {
        const PlRule *rule = &rules_[idx];
        if (!Matches(*rule, src, true, aSrc) || !Matches(*rule, tgt, false, aTgt)) {
            continue;
        }
        // An empty permission list on the rule is `*` -- it covers every
        // permission, so it must keep matching every request.
        if (rule->perms.empty()) {
            out->push_back(rule);
            continue;
        }
        bool overlap = false;
        for (SymId p : perms) {
            if (std::binary_search(rule->perms.begin(), rule->perms.end(), p)) {
                overlap = true;
                break;
            }
        }
        if (overlap) {
            out->push_back(rule);
        }
    }
}

bool PlIndex::HasAccess(SymId src, SymId tgt, SymId cls, const std::vector<SymId> &perms,
                        std::vector<SymId> *granted) const
{
    return HasAccessImpl(src, tgt, cls, perms, nullptr, false, granted);
}

bool PlIndex::HasAccessWithExtraAllow(SymId src, SymId tgt, SymId cls,
                                      const std::vector<SymId> &perms,
                                      const std::vector<SymId> &extra, bool ruleApplies,
                                      std::vector<SymId> *granted) const
{
    return HasAccessImpl(src, tgt, cls, perms, &extra, ruleApplies, granted);
}

bool PlIndex::HasAccessImpl(SymId src, SymId tgt, SymId cls, const std::vector<SymId> &perms,
                            const std::vector<SymId> *extra, bool extraApplies,
                            std::vector<SymId> *granted) const
{
    std::vector<const PlRule *> rules;
    AllowRules(src, tgt, cls, &rules);

    std::vector<SymId> acc;
    bool wildcard = false;
    for (const PlRule *rule : rules) {
        if (rule->perms.empty()) {
            wildcard = true;        // empty permission set == '*'
        } else {
            acc.insert(acc.end(), rule->perms.begin(), rule->perms.end());
        }
    }
    if (extra != nullptr && extraApplies) {
        // The synthesized patch rule. index.py:load_text() appends, so a
        // patched index is the union of the existing rules and this one -- and
        // a patch whose permission set is empty is the same wildcard here as
        // it is there. A rule that does not match this query contributes
        // nothing, exactly as it would not in Python.
        if (extra->empty()) {
            wildcard = true;
        } else {
            acc.insert(acc.end(), extra->begin(), extra->end());
        }
    }
    SortUnique(&acc);
    if (wildcard) {
        // A wildcard rule grants everything requested, whatever the set holds.
        acc.insert(acc.end(), perms.begin(), perms.end());
        SortUnique(&acc);
    }
    if (granted != nullptr) {
        // index.py:has_access reports the *requested* permissions that were
        // granted, not every permission the matching rules happen to carry: a
        // caller asking about {read} must not be told relabelto came with it.
        // Intersect with the request, keeping the wildcard behaviour already
        // folded into acc above.
        std::vector<SymId> matched;
        matched.reserve(perms.size());
        for (SymId perm : perms) {
            if (std::binary_search(acc.begin(), acc.end(), perm)) {
                matched.push_back(perm);
            }
        }
        SortUnique(&matched);
        *granted = matched;
    }
    for (SymId perm : perms) {
        if (!std::binary_search(acc.begin(), acc.end(), perm)) {
            return false;
        }
    }
    return true;
}

IoctlVerdict PlIndex::IoctlAllowed(SymId src, SymId tgt, SymId cls, SymId cmd) const
{
    return IoctlAllowedImpl(src, tgt, cls, cmd, nullptr, false);
}

IoctlVerdict PlIndex::IoctlAllowedWithExtraXperm(SymId src, SymId tgt, SymId cls,
                                                 SymId cmd,
                                                 const std::vector<SymId> &extra,
                                                 bool ruleApplies) const
{
    return IoctlAllowedImpl(src, tgt, cls, cmd, &extra, ruleApplies);
}

IoctlVerdict PlIndex::IoctlAllowedImpl(SymId src, SymId tgt, SymId cls, SymId cmd,
                                       const std::vector<SymId> *extra, bool extraApplies) const
{
    IoctlVerdict verdict;
    const std::vector<SymId> &aSrc = Attrs(src);
    const std::vector<SymId> &aTgt = Attrs(tgt);

    // The xperm pass wants both xperm kinds together, in rule-index order: the
    // scan this replaces walked the class ascending and the allowxperm and
    // neverallowxperm rules were interleaved in whatever order the policy
    // wrote them.
    std::vector<uint32_t> candidates, side, other;
    Candidates(RuleKind::kAllowXperm, true, cls, src, aSrc, &candidates);
    Candidates(RuleKind::kAllowXperm, false, cls, tgt, aTgt, &side);
    IntersectSorted(&candidates, side);
    Candidates(RuleKind::kNeverAllowXperm, true, cls, src, aSrc, &other);
    Candidates(RuleKind::kNeverAllowXperm, false, cls, tgt, aTgt, &side);
    IntersectSorted(&other, side);
    MergeSorted(&candidates, other);

    // Only xperm rules whose permission is literally "ioctl" participate --
    // compared as a name, not an interned id, because an empty permission
    // encodes as kNoSym and must not be confused with a real "ioctl".
    std::vector<SymId> whitelist;
    bool invertHit = false;
    for (uint32_t idx : candidates) {
        const PlRule *rule = &rules_[idx];
        if (rule->xpermPerm == kNoSym || syms_[rule->xpermPerm] != "ioctl") {
            continue;
        }
        if (!Matches(*rule, src, true, aSrc) || !Matches(*rule, tgt, false, aTgt)) {
            continue;
        }
        if (rule->kind == RuleKind::kAllowXperm) {
            whitelist.insert(whitelist.end(), rule->xperms.begin(), rule->xperms.end());
        } else if (cmd != kNoSym &&
                   std::binary_search(rule->xperms.begin(), rule->xperms.end(), cmd)) {
            // neverallowxperm '~{ ... }' blocks everything in its own set.
            invertHit = true;
        }
    }

    if (invertHit) {
        verdict.allowed = false;
        verdict.reason = "neverallowxperm";
        return verdict;
    }
    if (extra != nullptr && extraApplies) {
        // The synthesized allowxperm patch, unioned in before the whitelist is
        // consulted. The neverallowxperm check above still wins, as in Python.
        whitelist.insert(whitelist.end(), extra->begin(), extra->end());
    }
    SortUnique(&whitelist);
    if (!whitelist.empty()) {
        verdict.allowed = (cmd != kNoSym) &&
                          std::binary_search(whitelist.begin(), whitelist.end(), cmd);
        verdict.reason = "allowxperm";
        return verdict;
    }

    // Fall back to a plain allow that names ioctl explicitly. Note this is
    // membership in the rule's permission set, so an empty (wildcard) set does
    // NOT satisfy it -- has_access would grant it, ioctl_allowed does not.
    SymId ioctlSym = FindSym("ioctl");
    if (ioctlSym != kNoSym) {
        // A second, differently keyed candidate set: the one above holds xperm
        // rules only, and the fallback is about plain allows.
        Candidates(RuleKind::kAllow, true, cls, src, aSrc, &candidates);
        Candidates(RuleKind::kAllow, false, cls, tgt, aTgt, &side);
        IntersectSorted(&candidates, side);
        for (uint32_t idx : candidates) {
            const PlRule *rule = &rules_[idx];
            if (!Matches(*rule, src, true, aSrc) || !Matches(*rule, tgt, false, aTgt)) {
                continue;
            }
            if (std::binary_search(rule->perms.begin(), rule->perms.end(), ioctlSym)) {
                verdict.allowed = true;
                verdict.reason = "allow(ioctl)";
                return verdict;
            }
        }
    }
    verdict.allowed = false;
    verdict.reason = "no_allow";
    return verdict;
}

} // namespace policy_loop
