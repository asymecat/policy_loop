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

#ifndef POLICY_LOOP_PL_REPORT_H
#define POLICY_LOOP_PL_REPORT_H

#include <string>
#include <vector>

namespace policy_loop {

/*
 * The device-side facts that wrap a convergence report.
 *
 * The report body itself is the host engine's, field for field (see
 * ReportToJson), and is what the differential harness compares byte for byte.
 * This block is the opposite: facts only the device can know -- where the log
 * came from, how much of it the kernel threw away, how long the index took to
 * load. Keeping them in a separate key rather than scattered through the report
 * is what lets the harness treat the report as an exact comparison and this
 * block as an existence check.
 */
struct DeviceFacts {
    std::string indexRev;                   // sha1(payload)[:12], see PlIndex::rev()
    long long rulesLoaded = 0;
    long long skipped = 0;                  // PLI macros the exporter could not expand
    std::string source;                     // file|stdin|cmd|kmsg
    std::string sourceDesc;                 // for the header line
    long long lines = 0;                    // log lines read
    long long observedDenials = 0;          // report.total_denials, for the banner
    long long suppressedEstimate = 0;       // see CountSuppressed
    bool sampled = false;                   // source may have dropped records
    double loadMs = 0.0;
    double queryMs = 0.0;
    std::vector<std::string> warnings;
};

/*
 * Records the one caveat the exporter cannot fix: it cannot expand every `.te`
 * construct into PLI (macros in particular -- `skipped=647` on the rk3568 tree),
 * so the index is *incomplete*, and a query can answer "denied" where the
 * compiled policy the device is actually running allows. That qualifies every
 * verdict in the report, so it is surfaced as a warning rather than left in a
 * counter for someone to notice.
 */
void WarnIncompleteIndex(DeviceFacts *facts);

/*
 * Sums the "N callbacks suppressed" counts a rate-limited printk stream reports.
 *
 * The kernel's audit path emits `kauditd_printk_skb: N callbacks suppressed`
 * when printk's 5-second/10-message limit drops audit records, so the observed
 * denial count is a lower bound and this is the size of the gap. Only the audit
 * form is counted: the plain `printk: N callbacks suppressed` comes from every
 * subsystem that logs too fast, and folding those in would inflate the estimate
 * with records that were never denials. The figure is an estimate by
 * construction -- the kernel reports it in batches.
 */
long long CountSuppressed(const std::string &text);

// The report body with the `device` key merged in, as JSON.
std::string WithDeviceBlock(const std::string &reportJson, const DeviceFacts &facts);

/*
 * The one-line banner for stderr:
 *
 *   source=file  lines=5161  suppressed≈0  (sampled input; unique_cases is the
 *   robust metric)
 *
 * Printed to stderr rather than carried in the report so that stdout stays a
 * single parseable JSON document.
 */
std::string HeaderLine(const DeviceFacts &facts);

} // namespace policy_loop

#endif // POLICY_LOOP_PL_REPORT_H
