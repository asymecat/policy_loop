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

#include "pl_report.h"

#include <cstdio>
#include <cstring>

// For JsonString, the one JSON string encoder in the tool -- shared so the
// report body and the device block escape identically.
#include "pl_avc_parser.h"

namespace policy_loop {

namespace {

const char *const kSuppressedMarker = "kauditd_printk_skb:";
const char *const kSuppressedSuffix = " callbacks suppressed";

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

// Parses `kauditd_printk_skb:` <spaces> <digits> ` callbacks suppressed`,
// returning false when this occurrence is not that shape.
bool ParseSuppressedAt(const std::string &text, size_t pos, long long *count)
{
    if (text.compare(pos, std::strlen(kSuppressedMarker), kSuppressedMarker) != 0) {
        return false;
    }
    size_t i = pos + std::strlen(kSuppressedMarker);
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) {
        ++i;
    }
    size_t digits = i;
    long long value = 0;
    while (i < text.size() && IsDigit(text[i])) {
        // Saturate rather than wrap: a corrupt line must not turn a large
        // suppression count into a small (or negative) one.
        if (value < 1000000000LL) {
            value = value * 10 + (text[i] - '0');
        }
        ++i;
    }
    if (i == digits) {
        return false;
    }
    if (text.compare(i, std::strlen(kSuppressedSuffix), kSuppressedSuffix) != 0) {
        return false;
    }
    // The suffix must end at a word boundary. The kernel writes the message with
    // a leading space, and a single space is what stops this matching a longer
    // word; on the far side nothing does, so `...suppressedx` would otherwise be
    // counted -- the direction that inflates the estimate silently.
    size_t after = i + std::strlen(kSuppressedSuffix);
    if (after < text.size()) {
        char c = text[after];
        bool wordChar = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') || c == '_';
        if (wordChar) {
            return false;
        }
    }
    *count += value;
    return true;
}

} // namespace

long long CountSuppressed(const std::string &text)
{
    long long total = 0;
    size_t pos = 0;
    while ((pos = text.find(kSuppressedMarker, pos)) != std::string::npos) {
        if (ParseSuppressedAt(text, pos, &total)) {
            // Step past the matched command name; the rest of the line cannot
            // start another occurrence, but the search resumes from here so a
            // malformed one is not rescanned forever.
            pos += std::strlen(kSuppressedMarker);
        } else {
            pos += 1;
        }
    }
    return total;
}

void WarnIncompleteIndex(DeviceFacts *facts)
{
    if (facts->skipped <= 0) {
        return;
    }
    facts->warnings.push_back("skipped=" + std::to_string(facts->skipped) +
                              ", index recall may be incomplete");
}

std::string WithDeviceBlock(const std::string &reportJson, const DeviceFacts &facts)
{
    // The report body is compared byte for byte against the host engine's, so
    // it is spliced rather than re-serialized: only the trailing brace moves.
    size_t end = reportJson.find_last_of('}');
    if (end == std::string::npos) {
        return reportJson;                  // not JSON; leave it untouched
    }

    std::string out = reportJson.substr(0, end);
    out += ", \"device\": {\"index_rev\": " + JsonString(facts.indexRev);
    out += ", \"rules_loaded\": " + std::to_string(facts.rulesLoaded);
    out += ", \"skipped\": " + std::to_string(facts.skipped);
    out += ", \"source\": " + JsonString(facts.source);
    out += ", \"source_desc\": " + JsonString(facts.sourceDesc);
    out += ", \"lines\": " + std::to_string(facts.lines);
    out += ", \"suppressed_estimate\": " + std::to_string(facts.suppressedEstimate);
    out += ", \"sampled\": ";
    out += facts.sampled ? "true" : "false";
    out += ", \"overruns\": " + std::to_string(facts.overruns);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.1f", facts.loadMs);
    out += ", \"load_ms\": " + std::string(buf);
    std::snprintf(buf, sizeof(buf), "%.1f", facts.queryMs);
    out += ", \"query_ms\": " + std::string(buf);
    out += ", \"warnings\": [";
    for (size_t i = 0; i < facts.warnings.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += JsonString(facts.warnings[i]);
    }
    // Three closes: the warnings array, the device object, and the report object
    // whose own brace the truncation above removed.
    out += "]}}";
    out += reportJson.substr(end + 1);      // whatever followed the brace (a newline)
    return out;
}

std::string HeaderLine(const DeviceFacts &facts)
{
    std::string out = "source=" + facts.source;
    if (!facts.sourceDesc.empty() && facts.sourceDesc != facts.source) {
        out += "(" + facts.sourceDesc + ")";
    }
    out += "  lines=" + std::to_string(facts.lines);
    out += "  suppressed≈" + std::to_string(facts.suppressedEstimate);
    // Fixed suffix, printed whether or not the source is lossy: read from a file
    // the count is exact and the caveat is inert, and a banner whose shape
    // changes from run to run is one nobody learns to read.
    out += "  (sampled input; unique_cases is the robust metric)";
    if (facts.suppressedEstimate > 0) {
        // Spelled out as a sum rather than a total: the suppressed figure is a
        // rate-limiter estimate reported in batches, so it bounds the loss
        // rather than pinning it, and a single added-up number would read as
        // more precise than it is.
        out += "\nactual denials may be " + std::to_string(facts.observedDenials) + " + " +
               std::to_string(facts.suppressedEstimate);
    }
    if (facts.overruns > 0) {
        // Distinct from the rate-limiter estimate above: those records were
        // never written, these were written and then overwritten in the ring
        // before the reader got to them. Same consequence (the count is a lower
        // bound) but a different cause, and only one of the two is fixable by
        // reading faster.
        out += "\n" + std::to_string(facts.overruns) +
               " ring overrun(s): records were overwritten before they could be read";
    }
    return out;
}

} // namespace policy_loop
