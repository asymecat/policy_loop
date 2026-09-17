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

#include "pl_avc_parser.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "pl_sha1.h"

namespace policy_loop {
namespace {

// --------------------------------------------------------------------------
// Character classes
// --------------------------------------------------------------------------

// Python's `\s` on str is Unicode-aware; this is the ASCII subset. Audit logs
// are ASCII in every field this parser reads, and matching bytes >= 0x80 as
// whitespace would corrupt UTF-8 text, so the ASCII set is both safer and what
// the corpus exercises. Any divergence here would show up as a parse difference
// in the differential harness.
inline bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

inline bool IsWordChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

inline char Lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

inline bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

// Python str.splitlines() separators, ASCII subset. Note that \v and \f DO
// split lines in Python, which matters for logs that embed control bytes.
inline bool IsLineBreak(char c)
{
    return c == '\n' || c == '\r' || c == '\v' || c == '\f' ||
           c == '\x1c' || c == '\x1d' || c == '\x1e';
}

bool MatchNoCase(const std::string &text, size_t pos, const char *needle)
{
    size_t i = 0;
    while (needle[i] != '\0') {
        if (pos + i >= text.size() || Lower(text[pos + i]) != needle[i]) {
            return false;
        }
        ++i;
    }
    return true;
}

// `\b` at the start of a literal: the preceding byte must not be a word char.
inline bool WordBoundaryAt(const std::string &text, size_t pos)
{
    return pos == 0 || !IsWordChar(text[pos - 1]);
}

// --------------------------------------------------------------------------
// Small string helpers (Python semantics)
// --------------------------------------------------------------------------

std::string StripBoth(const std::string &s)
{
    size_t begin = 0;
    size_t end = s.size();
    while (begin < end && IsSpace(s[begin])) {
        ++begin;
    }
    while (end > begin && IsSpace(s[end - 1])) {
        --end;
    }
    return s.substr(begin, end - begin);
}

std::string StripLeft(const std::string &s)
{
    size_t begin = 0;
    while (begin < s.size() && IsSpace(s[begin])) {
        ++begin;
    }
    return s.substr(begin);
}

// Python str.split() with no arguments: split on whitespace runs, drop empties.
std::vector<std::string> SplitWhitespace(const std::string &s)
{
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && IsSpace(s[i])) {
            ++i;
        }
        if (i >= s.size()) {
            break;
        }
        size_t start = i;
        while (i < s.size() && !IsSpace(s[i])) {
            ++i;
        }
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

// Python str.replace(): non-overlapping, left to right.
std::string ReplaceAll(const std::string &s, const std::string &from, const std::string &to)
{
    if (from.empty()) {
        return s;
    }
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        if (s.compare(i, from.size(), from) == 0) {
            out += to;
            i += from.size();
        } else {
            out.push_back(s[i]);
            ++i;
        }
    }
    return out;
}

std::vector<std::string> SplitLines(const std::string &s)
{
    std::vector<std::string> out;
    size_t start = 0;
    size_t i = 0;
    while (i < s.size()) {
        char c = s[i];
        if (!IsLineBreak(c)) {
            ++i;
            continue;
        }
        out.push_back(s.substr(start, i - start));
        // \r\n counts as a single break, as in Python.
        if (c == '\r' && i + 1 < s.size() && s[i + 1] == '\n') {
            ++i;
        }
        ++i;
        start = i;
    }
    // A trailing break does not produce an empty final line.
    if (start < s.size()) {
        out.push_back(s.substr(start));
    }
    return out;
}

// --------------------------------------------------------------------------
// `avc : denied` marker
// --------------------------------------------------------------------------

// `\bavc\s*:\s*denied`, case-insensitive. \s* may match empty, so `avc:denied`,
// `AVC : DENIED` and `avc:  denied` all qualify -- but `avcx:` does not, because
// the \s* then has nothing to consume before the colon.
bool MatchAvcStart(const std::string &text, size_t pos, size_t *end)
{
    if (!WordBoundaryAt(text, pos) || !MatchNoCase(text, pos, "avc")) {
        return false;
    }
    size_t i = pos + 3;
    while (i < text.size() && IsSpace(text[i])) {
        ++i;
    }
    if (i >= text.size() || text[i] != ':') {
        return false;
    }
    ++i;
    while (i < text.size() && IsSpace(text[i])) {
        ++i;
    }
    if (!MatchNoCase(text, i, "denied")) {
        return false;
    }
    *end = i + 6;
    return true;
}

std::vector<size_t> FindAvcStarts(const std::string &text)
{
    std::vector<size_t> starts;
    size_t i = 0;
    while (i < text.size()) {
        size_t end = 0;
        if (MatchAvcStart(text, i, &end)) {
            starts.push_back(i);
            i = end;
        } else {
            ++i;
        }
    }
    return starts;
}

bool HasAvcStart(const std::string &text)
{
    for (size_t i = 0; i < text.size(); ++i) {
        size_t end = 0;
        if (MatchAvcStart(text, i, &end)) {
            return true;
        }
    }
    return false;
}

// Start of the line containing *pos*: Python text.rfind("\n", 0, pos) + 1.
size_t LineStart(const std::string &text, size_t pos)
{
    if (pos == 0) {
        return 0;
    }
    size_t nl = text.rfind('\n', pos - 1);
    return (nl == std::string::npos) ? 0 : nl + 1;
}

// --------------------------------------------------------------------------
// Permission set:  denied { read write }
// --------------------------------------------------------------------------

// `\bdenied\s*\{\s*(?P<perms>[^}]*?)\s*\}`, case-insensitive, first match wins.
//
// The lazy group plus the greedy \s* on either side means the captured set is
// the brace body with surrounding whitespace removed -- so splitting the raw
// body on whitespace is equivalent, and is what the Python side does with
// m.group("perms").split() anyway.
std::vector<std::string> ExtractPermissions(const std::string &text)
{
    for (size_t i = 0; i < text.size(); ++i) {
        if (!WordBoundaryAt(text, i) || !MatchNoCase(text, i, "denied")) {
            continue;
        }
        size_t j = i + 6;
        while (j < text.size() && IsSpace(text[j])) {
            ++j;
        }
        if (j >= text.size() || text[j] != '{') {
            continue;           // not a permission block; keep scanning
        }
        ++j;
        // [^}]*? cannot contain '}', so the group ends at the first '}'.
        size_t close = text.find('}', j);
        if (close == std::string::npos) {
            continue;
        }
        return SplitWhitespace(text.substr(j, close - j));
    }
    return {};
}

// --------------------------------------------------------------------------
// key=value fields
// --------------------------------------------------------------------------

// The 16 keys of the upstream alternation, in order. `dev`, `ino`, `sid`, `uid`
// and `gid` are not stored on the record but must still be *consumed*: skipping
// them would let the scanner rescan their bytes and pick up a key that Python's
// leftmost-match scan would have stepped over.
const char *const kKvKeys[] = {
    "pid", "comm", "path", "name", "dev", "ino", "ioctlcmd", "scontext",
    "tcontext", "tclass", "permissive", "parameter", "service", "sid", "uid", "gid",
};

/*
 * Match `\s*=\s*` then a value, starting at *pos* (just past the key).
 *
 * Value is `"..."` -- where a backslash escapes the next character, but not a
 * newline -- falling back to `[^\s,]+`. The fallback matters: for an
 * unterminated quote Python's alternation fails the quoted branch and matches
 * the bare one from the *same* position, yielding a value with a leading quote.
 */
bool MatchKvValue(const std::string &text, size_t pos, size_t *end)
{
    if (pos < text.size() && text[pos] == '"') {
        size_t k = pos + 1;
        bool terminated = false;
        while (k < text.size()) {
            if (text[k] == '"') {
                *end = k + 1;
                terminated = true;
                break;
            }
            if (text[k] == '\\') {
                if (k + 1 >= text.size() || text[k + 1] == '\n') {
                    break;      // `\\.` does not match a newline
                }
                k += 2;
                continue;
            }
            ++k;
        }
        if (terminated) {
            return true;
        }
    }
    size_t k = pos;
    while (k < text.size() && !IsSpace(text[k]) && text[k] != ',') {
        ++k;
    }
    if (k == pos) {
        return false;
    }
    *end = k;
    return true;
}

// Find every key=value pair; the first occurrence of a key wins (Python uses
// dict.setdefault over finditer, i.e. leftmost match per key).
void ScanKv(const std::string &text, std::vector<std::pair<std::string, std::string>> *out)
{
    size_t i = 0;
    while (i < text.size()) {
        bool matched = false;
        for (const char *key : kKvKeys) {
            size_t keyLen = std::char_traits<char>::length(key);
            if (text.compare(i, keyLen, key) != 0) {
                continue;
            }
            size_t afterKey = i + keyLen;
            size_t eq = afterKey;
            while (eq < text.size() && IsSpace(text[eq])) {
                ++eq;
            }
            if (eq >= text.size() || text[eq] != '=') {
                continue;
            }
            size_t valueStart = eq + 1;
            while (valueStart < text.size() && IsSpace(text[valueStart])) {
                ++valueStart;
            }
            size_t valueEnd = 0;
            if (!MatchKvValue(text, valueStart, &valueEnd)) {
                continue;
            }
            bool seen = false;
            for (const auto &entry : *out) {
                if (entry.first == key) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                out->emplace_back(key, text.substr(valueStart, valueEnd - valueStart));
            }
            i = valueEnd;
            matched = true;
            break;
        }
        if (!matched) {
            ++i;
        }
    }
}

const std::string *KvGet(const std::vector<std::pair<std::string, std::string>> &kv, const char *key)
{
    for (const auto &entry : kv) {
        if (entry.first == key) {
            return &entry.second;
        }
    }
    return nullptr;
}

// Strips one layer of surrounding double quotes.
std::string StripQuotes(const std::string &value)
{
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

// u:r:media_service:s0 -> "media_service"; fewer than 3 parts yields "".
std::string ContextType(const std::string &context)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t colon = context.find(':', start);
        if (colon == std::string::npos) {
            parts.push_back(context.substr(start));
            break;
        }
        parts.push_back(context.substr(start, colon - start));
        start = colon + 1;
    }
    return parts.size() > 2 ? parts[2] : std::string();
}

// --------------------------------------------------------------------------
// Event assembly
// --------------------------------------------------------------------------

DenialRecord ParseEvent(const std::string &text)
{
    DenialRecord rec;
    rec.permissions = ExtractPermissions(text);

    std::vector<std::pair<std::string, std::string>> kv;
    ScanKv(text, &kv);

    // Upstream guards scontext/tcontext with `if sctx` -- a *falsy* test -- so
    // `scontext=""` yields None rather than an empty type, while tclass is read
    // with a plain dict.get() and keeps its empty value. Reproducing that
    // asymmetry matters: the two serialize differently in the fingerprint
    // ("null" vs "\"\""), so collapsing either side would merge distinct cases.
    if (const std::string *sctx = KvGet(kv, "scontext")) {
        std::string value = StripQuotes(*sctx);
        if (!value.empty()) {
            rec.source_domain = OptStr(ContextType(value));
        }
    }
    if (const std::string *tctx = KvGet(kv, "tcontext")) {
        std::string value = StripQuotes(*tctx);
        if (!value.empty()) {
            rec.target_type = OptStr(ContextType(value));
        }
    }
    if (const std::string *tclass = KvGet(kv, "tclass")) {
        rec.tclass = OptStr(StripQuotes(*tclass));
    }

    // Anything other than 0/1 leaves the flag unknown, matching Python's
    // `== "1" if raw in ("0", "1") else None`.
    if (const std::string *perm = KvGet(kv, "permissive")) {
        std::string value = StripQuotes(*perm);
        if (value == "0") {
            rec.permissive = Permissive::kEnforcing;
        } else if (value == "1") {
            rec.permissive = Permissive::kPermissive;
        }
    }

    if (const std::string *comm = KvGet(kv, "comm")) {
        rec.comm = OptStr(StripQuotes(*comm));
    }
    if (const std::string *pid = KvGet(kv, "pid")) {
        std::string value = StripQuotes(*pid);
        bool digits = !value.empty() &&
                      std::all_of(value.begin(), value.end(), [](char c) { return IsDigit(c); });
        if (digits) {
            rec.hasPid = true;
            rec.pid = std::strtoll(value.c_str(), nullptr, 10);
        }
    }
    if (const std::string *path = KvGet(kv, "path")) {
        rec.path = OptStr(StripQuotes(*path));
    }
    if (const std::string *name = KvGet(kv, "name")) {
        rec.name = OptStr(StripQuotes(*name));
    }
    if (const std::string *ioctlcmd = KvGet(kv, "ioctlcmd")) {
        rec.ioctlCmd = OptStr(StripQuotes(*ioctlcmd));
    }
    if (const std::string *parameter = KvGet(kv, "parameter")) {
        rec.parameter = OptStr(StripQuotes(*parameter));
    }
    if (const std::string *service = KvGet(kv, "service")) {
        rec.service = OptStr(StripQuotes(*service));
    }

    rec.raw = StripBoth(text);
    return rec;
}

// --------------------------------------------------------------------------
// JSON (only enough of it to reproduce json.dumps for the fingerprint payload)
// --------------------------------------------------------------------------

// Python None serializes as null; an absent OptStr is exactly that.
void AppendJsonOptStr(std::string *out, const OptStr &value)
{
    if (value.present) {
        *out += JsonString(value.value);
    } else {
        *out += "null";
    }
}

} // namespace

// json.dumps(..., ensure_ascii=False) string escaping: quote, backslash, the
// short control escapes, and \uXXXX for the rest of C0. Bytes >= 0x20 pass
// through untouched, which keeps UTF-8 sequences intact.
std::string JsonString(const std::string &value)
{
    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
    return out;
}

std::string FingerprintPayload(const DenialRecord &rec)
{
    // json.dumps(key, sort_keys=True, ensure_ascii=False) with the default
    // separators: sorted key order, ", " between items and ": " after a key.
    std::vector<std::string> perms = rec.permissions;
    std::sort(perms.begin(), perms.end());

    std::string payload = "{\"cls\": ";
    AppendJsonOptStr(&payload, rec.tclass);
    payload += ", \"ioctl\": ";
    AppendJsonOptStr(&payload, rec.ioctlCmd);
    payload += ", \"perms\": [";
    for (size_t i = 0; i < perms.size(); ++i) {
        if (i != 0) {
            payload += ", ";
        }
        payload += JsonString(perms[i]);
    }
    payload += "], \"src\": ";
    AppendJsonOptStr(&payload, rec.source_domain);
    payload += ", \"tgt\": ";
    AppendJsonOptStr(&payload, rec.target_type);
    payload += "}";
    return payload;
}

std::string Fingerprint(const DenialRecord &rec)
{
    return Sha1Hex(FingerprintPayload(rec)).substr(0, 12);
}

std::vector<DenialRecord> ParseDenials(const std::string &input)
{
    // Backslash-newline joins a wrapped log line into its predecessor.
    std::string text = ReplaceAll(input, "\\\n", " ");

    std::vector<size_t> starts = FindAvcStarts(text);
    if (starts.empty()) {
        return {};
    }

    // Boundaries snap to the start of the line carrying each marker, so a
    // prefix on that line (e.g. "audit: type=1400 audit(...):") stays with its
    // own event rather than with the previous one.
    std::vector<size_t> bounds;
    bounds.reserve(starts.size() + 1);
    for (size_t start : starts) {
        bounds.push_back(LineStart(text, start));
    }
    if (bounds.back() != text.size()) {
        bounds.push_back(text.size());
    }

    std::vector<DenialRecord> records;
    for (size_t i = 0; i + 1 < bounds.size(); ++i) {
        std::string block = text.substr(bounds[i], bounds[i + 1] - bounds[i]);
        std::vector<std::string> lines;
        for (const std::string &line : SplitLines(block)) {
            if (line.empty() || StripBoth(line).empty()) {
                continue;
            }
            // Drop interleaved '#' comments, except lines that themselves carry
            // an event marker: upstream .te files keep real denials as comments
            // and those are meant to be parsed.
            if (StripLeft(line).front() == '#' && !HasAvcStart(line)) {
                continue;
            }
            lines.push_back(line);
        }
        if (lines.empty()) {
            continue;
        }
        std::string joined;
        for (size_t k = 0; k < lines.size(); ++k) {
            if (k != 0) {
                joined.push_back('\n');
            }
            joined += lines[k];
        }
        records.push_back(ParseEvent(joined));
    }
    return records;
}

} // namespace policy_loop
