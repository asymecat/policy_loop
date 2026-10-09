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

#ifndef POLICY_LOOP_PL_CONVERGE_H
#define POLICY_LOOP_PL_CONVERGE_H

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "pl_avc_parser.h"
#include "pl_index.h"

namespace policy_loop {

/*
 * Port of policy_loop/converge.py.
 *
 * The host engine runs a six-agent pipeline (Log -> Policy -> Security ->
 * Repair -> Reviewer -> Verify) per unique case. The device has no use for the
 * agent objects -- there is nothing to orchestrate, no provider, no trace --
 * so the pipeline is collapsed here into the closed-form verdict it computes:
 * classify, build the minimal patch, review it, verify it, bucket it. The
 * acceptance metric is unchanged and is what the differential harness checks:
 * for every cluster, the category, classification, patch text, review status,
 * verify status and reason must equal the host engine's, byte for byte.
 *
 * This tool never writes policy. It emits suggested rules as text; that is a
 * hard design constraint, not a missing feature.
 */

// converge.py CAT_* -- the buckets a cluster can land in.
extern const char *const kCatAuto;          // auto_repairable
extern const char *const kCatHuman;         // needs_human
extern const char *const kCatNoise;         // noise_or_already_allowed
extern const char *const kCatUnclassified;  // unclassified_no_policy

/*
 * One unique logical access (a fingerprint group) and its pipeline outcome.
 * Field for field the Python converge.Cluster.
 */
struct Cluster {
    std::string fp;
    long long count = 0;
    long long permissive = 0;
    long long enforcing = 0;
    long long permissiveUnknown = 0;
    std::string src;
    std::string tgt;
    std::string cls;
    std::vector<std::string> perms;         // first record's log order
    std::string ioctl;
    std::vector<std::string> comms;         // first 5 distinct, in order
    std::string sampleRaw;
    std::string category = kCatUnclassified;
    std::string classification;
    std::string patch;
    std::string reviewStatus;
    std::string verifyStatus;
    std::string why;
};

struct PatchStat {
    long long cases = 0;
    long long denials = 0;
};

struct HumanItem {
    std::string caseId;
    long long count = 0;
    std::string src;
    std::string tgt;
    std::string cls;
    std::vector<std::string> perms;         // sorted
    std::string classification;
    std::string review;
    std::string verify;
    std::string why;
    std::string sample;                     // sample_raw truncated to 200 chars
};

// A counted bucket list that preserves first-insertion order, the way Python's
// collections.Counter does -- dict iteration order is observable in the JSON
// report, so it is part of the parity contract rather than an accident.
using CountedList = std::vector<std::pair<std::string, long long>>;

struct ConvergeReport {
    long long totalDenials = 0;
    long long uniqueCases = 0;
    CountedList byCategory;
    CountedList byClassification;
    std::vector<Cluster> clusters;
    std::vector<std::string> autoPatchLines;              // sorted, deduped
    std::vector<std::pair<std::string, PatchStat>> autoPatchStats;  // by patch, sorted
    std::vector<HumanItem> humanItems;
    long long noiseCases = 0;
    std::string targetNote;
};

/*
 * Cluster *records* by logical access and, when *index* is non-null, run the
 * convergence pipeline on each cluster. A null index reproduces converge.py's
 * "no policy" mode, where every case stays unclassified.
 *
 * The index is non-const because a query interns the permissions the log asks
 * about -- including names the policy never declares, which a wildcard allow
 * must still report as granted (see QueryBatch).
 */
ConvergeReport Converge(const std::vector<DenialRecord> &records, PlIndex *index);

/*
 * The report as JSON, mirroring Python's ConvergeReport.to_dict() so the host
 * engine's report can be compared field by field.
 */
std::string ReportToJson(const ConvergeReport &report);

/*
 * ---------------------------------------------------------------------------
 * Per-record API
 * ---------------------------------------------------------------------------
 *
 * The batch entry points above answer "what does this whole log amount to".
 * This one answers "what does this one denial amount to", and it is the fixed
 * surface a host-side driver uses when it wants to walk the cases itself --
 * feeding one record at a time -- instead of asking the device for a finished
 * report. Converge and ExplainDenial are expressed on top of it, so a per-record
 * answer and the corresponding line of the batch report cannot drift apart.
 */

/*
 * ---------------------------------------------------------------------------
 * The cross-layer view
 * ---------------------------------------------------------------------------
 *
 * A denial whose `scontext` is `u:r:normal_hap` does not name an application --
 * it names *every* normal-APL application on the device, because the platform
 * derives an app's domain from the APL in its signing profile rather than from
 * its bundle. So "add `allow normal_hap sys_file:file read`" is a platform-wide
 * grant, not a fix for one app; whether that grant is the right answer, or
 * whether the platform is defending an APL boundary on purpose, cannot be read
 * off the `.te` tree at all. It takes the bridge in `sehap_contexts`, which the
 * PLI carries as `@hap` (see PlHapEntry).
 *
 * This is the port of policy_loop/policy/cross_layer.py:analyze. It is advice,
 * not a verdict: it never changes a classification, a patch, or a bucket, and
 * nothing in the convergence pipeline reads it back. That separation is
 * load-bearing -- the batch report is byte-compared against the host engine
 * (tests/diff_device.py), and a cross-layer answer that moved a case between
 * buckets would make the two disagree.
 *
 * `variants[*].source` (the sehap_contexts file the host read an entry from) is
 * the one host field with no device counterpart: it is a build-machine path,
 * and the PLI deliberately does not carry it. Nothing reads it.
 */
struct CaseVerdict;   // declared below; the view only reads one

struct CrossLayerView {
    // False when the scontext is not an app domain at all -- which is the
    // common case, and an answer rather than an error. The other fields are
    // then the short form: no APL, no scope, no boundary.
    bool app = false;
    // An absent field renders as null in the JSON, not as the literal "None"
    // the top-level `tgt`/`cls` keys use: this view is built from the same
    // Optional values the host agent passes, so it keeps them optional.
    bool domainPresent = false;
    bool targetPresent = false;
    bool clsPresent = false;
    std::string domain;
    std::string target;
    std::string cls;
    std::vector<std::string> apl;           // distinct levels, ascending
    bool debuggable = false;
    bool multiLevelDomain = false;
    std::string scope;
    std::string resolvedTarget;             // "" when the placeholder did not resolve
    std::vector<std::string> perms;         // sorted, deduped
    std::string fixLayer;                   // app / system / none
    std::string headline;
    std::vector<std::string> advice;
    std::vector<std::string> evidence;
    std::vector<PlHapEntry> variants;       // every entry declaring `domain`

    // `boundary` and `debug_pair` are null unless the view is an app-domain one.
    bool hasBoundary = false;
    struct Boundary {
        long long checked = 0;
        // domain -> its APL levels; emitted as a JSON object, so the host's
        // sort_keys ordering is what decides the field order.
        std::vector<std::pair<std::string, std::vector<std::string>>> allowing;
        std::vector<std::string> higherAplAllowing;
        std::vector<std::string> uncovered;
    } boundary;

    bool hasDebugPair = false;
    struct DebugPair {
        std::string kind;                   // none / same_domain / sibling
        std::string domain;
        bool hasAllows = false;             // false -> null (kind != sibling)
        bool allows = false;
    } debugPair;
};

/*
 * The cross-layer view of one denial, or a view with `app == false` when the
 * index carries no APL bridge at all... which cannot happen here: an index
 * without `@hap` lines yields an empty table and every scontext is then "not an
 * app domain", so the caller always gets an object. The host returns None in
 * that case instead, and the host's caller omits the key; the device caller
 * checks `index->hapEntries().empty()` for the same decision, which is why this
 * returns a view rather than a pointer.
 *
 * *index* must not be null, and is non-const for the reason Converge's is: a
 * query interns the permissions the log asks about, including names the policy
 * never declares -- a wildcard allow must still report those as granted, in
 * this view exactly as in the pipeline. *rec* supplies `service`, the target
 * the M3 resolution needs, and the Optional-ness the host agent keeps; *verdict*
 * supplies the requested set and the already-computed `allAllowed` (the view
 * must not pay for a query the pipeline already ran).
 */
CrossLayerView CrossLayerViewOf(PlIndex *index, const DenialRecord &rec,
                                const CaseVerdict &verdict);

/*
 * Which of the two settle paths to take. They are not interchangeable: they do
 * not agree on wording. A case that is already allowed is settled cheaply by
 * converge.py's `_quick` with a short reason ("策略已允许（历史/噪声）"), while the
 * full pipeline answers the same case with SecurityAgent's recommendation title
 * ("无需修复（噪声/已修复）"). The batch report carries the former, so a caller
 * that needs byte parity with the report must ask for kQuickThenPipeline.
 */
enum class CasePath {
    // converge.py: settle neverallow hits and already-allowed cases cheaply and
    // only run the pipeline when a real repair decision is needed.
    kQuickThenPipeline,
    // explain: always the full closed-form pipeline, so a developer holding one
    // line gets the answer the six agents would give it -- the recommendation
    // and its patch. The guards are a separate step (see ApplyGuards) rather
    // than part of this one, but both paths take it, which is why they cannot
    // disagree about whether a patch is fit to apply unattended.
    kFullPipeline,
};

/*
 * One denial, decided. Field for field what the corresponding pipeline stage
 * produces -- nothing here is recomputed or reinterpreted.
 *
 * The two settle paths are both represented and stay distinguishable through
 * `quickSettled`: when it is true, `why` is the quick path's reason and the
 * `patch`/`reviewStatus`/`verifyStatus` fields were never computed (the pipeline
 * was not run, and running it would have changed `why`). Reading those fields
 * without checking the flag means reading stale empties.
 */
struct CaseVerdict {
    // --- policy query stage (BuildVerdict) ---
    // `src`/`tgt`/`cls` render an absent field as the literal token "None", the
    // way PolicyAgent's Optional interpolation does -- that token is what the
    // patch text spells and what the verify step then cannot match.
    std::string src;
    std::string tgt;
    std::string cls;
    std::vector<std::string> requested;     // sorted, deduped
    std::vector<std::string> granted;       // sorted, deduped
    std::vector<std::string> missing;       // sorted: requested - granted
    bool allAllowed = false;
    std::size_t neverallowHits = 0;
    bool hasIoctl = false;
    bool ioctlAllowed = false;
    std::string ioctlReason;
    std::string ioctlCmd;                   // empty unless the denial carried one

    // --- which path settled the case, and what it decided ---
    bool quickSettled = false;              // true -> the quick path wrote the three below
    std::string category;                   // kCat* bucket, either path
    std::string classification;             // SecurityAgent.classify
    // The answer, in one sentence: the quick path's reason, or the pipeline's
    // recommendation title. Once the guards have run, a downgrade replaces it
    // with the guard's reason -- that *is* the answer for such a case -- and
    // `advisory` keeps the two tellable apart.
    std::string why;

    // --- full pipeline only (meaningful when !quickSettled) ---
    std::string patch;                      // "" when no patch is proposed
    std::string reviewStatus;               // APPROVE / REJECT / SKIP
    std::string verifyStatus;               // SUCCESS / FAILED / ...
    bool needsHuman = false;
    bool producedPatch = false;

    // --- the guards (meaningful only once ApplyGuards has run) ---
    // A verdict straight out of ExplainCase has decided *what is wrong and how
    // one would fix it*; whether that fix may be applied unattended is a
    // separate question the guards answer, and a caller that never asks it must
    // not read these as "not safe". `guardsApplied` is what separates the two.
    bool guardsApplied = false;
    bool autoSafe = false;                  // survived every guard
    std::string advisory;                   // downgraded: why it must not be applied
};

/*
 * Decide one already-parsed denial. *index* is non-const for the same reason
 * Converge's is: a query interns the permissions the log asks about, including
 * names the policy never declares. A null index is the "no policy" mode -- the
 * record's own fields are mirrored back and nothing is classified.
 *
 * Parsing is deliberately not part of this call: the host owns line handling and
 * passes a record it has already accounted for.
 */
CaseVerdict ExplainCase(const DenialRecord &rec, PlIndex *index, CasePath path);

/*
 * The six guards, as a step the caller takes deliberately.
 *
 * They answer a different question from the verdict. ExplainCase says what is
 * wrong and what rule would close the gap; the guards say whether that rule is
 * safe to apply *without a human* -- is the target a real type, does the
 * subject exist in this corpus, could the patch land at all. Converge asks that
 * about every auto-repairable case, so its report buckets reflect the guards.
 *
 * Applies in place: on a downgrade `category` becomes needs_human and `advisory`
 * carries the reason, which is the sentence a caller shows beside the patch.
 * On a case that survives, `category` is unchanged, `autoSafe` is true and
 * `advisory` stays empty. `guardsApplied` is set either way.
 *
 * A verdict that is not auto_repairable is returned untouched apart from the
 * flag: the guards only ever fire on a case the pipeline judged safe to repair,
 * and there is nothing to guard on a case already going to a human.
 *
 * *requireAuto* is that rule, and it is the batch contract. The single-denial
 * path turns it off, because there the question is asked of every answer: a
 * developer holding one line is shown a patch whatever bucket the case landed
 * in, and if that patch cannot land they have to be told. Gating it on the
 * bucket is what let `--explain` recommend a rule against a `default_*`
 * placeholder while the report filed the same line as needs_human.
 */
void ApplyGuards(const DenialRecord &rec, PlIndex *index, CaseVerdict *verdict,
                 bool requireAuto = true);

/*
 * CaseVerdict as JSON, one object, keys sorted, trailing newline -- the same
 * shape contract ReportToJson and ExplainToJson follow, so a host driver can
 * compare the device's per-record answer against its own with `diff`.
 *
 * Every field is emitted, including the ones a settled path did not compute:
 * `quick_settled` is what tells an empty `patch` apart from a pipeline that
 * never ran, so the flag and the field have to travel together.
 */
std::string CaseVerdictToJson(const CaseVerdict &verdict);

/*
 * security_agent._HUMAN -- the plain-language explanation of one denial.
 *
 * This is the one piece of the host agent pipeline converge never needed: the
 * batch report carries only a machine classification, so the wording stayed
 * behind in Python (see the note above RunPipeline in the .cpp). It is needed
 * again now that the tool answers a developer's single denial, and it is part
 * of the parity contract for the same reason everything else is -- the host and
 * the device must say the same words about the same denial.
 *
 * *requested* and *granted* are the sorted, deduped permission lists a verdict
 * carries (Python sorts both the same way). *ioctlCmd* is the denied command
 * number, read only by the XPERM_GAP branch. An unknown classification yields
 * the empty string rather than a guess.
 */
std::string ExplainHuman(const std::string &classification,
                         const std::string &src, const std::string &tgt,
                         const std::string &cls,
                         const std::vector<std::string> &requested,
                         const std::vector<std::string> &granted,
                         const std::string &ioctlCmd);

/*
 * One denial, answered: what the policy says about it and what to do next.
 *
 * This is the single-case view of the same pipeline Converge runs in batch --
 * BuildVerdict, Classify, RunPipeline -- not a second implementation of it. The
 * point of the tool's `--explain` mode is that a developer holding one
 * `avc: denied` line gets the same answer the batch report would have given that
 * case, so the two must not be able to drift apart.
 *
 * The batch-only guards are deliberately absent: those decide whether a patch is
 * safe to apply *automatically* in a report. Nothing here is applied at all --
 * the output is advice for a human -- so `patch` is reported as computed, and
 * `reviewStatus`/`verifyStatus` carry the reviewer's and verifier's verdict on
 * it for the reader to weigh.
 */
struct ExplainResult {
    bool parsed = false;                    // false: the line held no denial
    std::string src;
    std::string tgt;
    std::string cls;
    std::vector<std::string> requested;     // sorted, deduped
    std::vector<std::string> granted;       // sorted, deduped
    std::vector<std::string> missing;       // sorted: requested - granted
    std::string ioctlCmd;                   // empty unless the denial carried one
    std::string classification;             // SecurityAgent.classify
    std::string explanation;                // security_agent._HUMAN wording
    std::string recommendedId;              // A / B / C / -
    std::string recommendedTitle;           // case.recommended.title
    // Empty when no guard fired. Otherwise the reason this patch must not be
    // applied unattended, which is also what `recommendedTitle` carries by then:
    // for a downgraded case the answer *is* the reason it was downgraded. Both
    // are emitted so a reader can tell which part of the answer the guards
    // contributed. `needsHuman` is deliberately not touched -- the batch report
    // expresses the same downgrade through the cluster's bucket, and inventing a
    // second signal here would word the two paths differently.
    std::string advisory;
    // The application-layer view. Only filled when the caller asked for it
    // (`withCrossLayer`), and only *set* when the index carries an APL bridge
    // at all: an index exported from a single `.te` file has no
    // sehap_contexts, the host's `analyze` returns None for it, and the host's
    // caller then omits the key entirely rather than emitting an empty view.
    // `hasCrossLayer` is that distinction, and it is what the JSON follows.
    bool hasCrossLayer = false;
    CrossLayerView crossLayer;
    bool needsHuman = false;
    std::string patch;                      // "" when no patch is proposed
    std::string reviewStatus;               // APPROVE / REJECT / SKIP
    std::string verifyStatus;               // SUCCESS / FAILED / ... / SKIP-a-like
};

/*
 * Explain the first denial in *line*. *index* must outlive the call and must not
 * be null: every field above except the parsed record itself is a question put to
 * the policy, and answering them without one would mean guessing.
 *
 * A line that holds no denial returns a result with `parsed == false` rather than
 * an error: "this is not a denial" is an answer a caller wants to print, and it is
 * the common case when a line is pasted from the wrong place.
 */
ExplainResult ExplainDenial(const std::string &line, PlIndex *index,
                            bool withCrossLayer = false);

/*
 * ExplainResult as JSON, one object, keys sorted, `json.dumps`'s default
 * separators, trailing newline -- the same shape contract ReportToJson follows.
 * The host's single-case path emits the same object, so the differential
 * harness compares the two with `diff` instead of walking fields.
 *
 * An absent ioctl command renders as null rather than ""; a denial either
 * carried one or did not, and an empty string would suggest it carried an empty
 * one.
 *
 * `cross_layer` is present only when `hasCrossLayer` is set -- that is, when
 * the caller asked for the view *and* the index has an APL bridge to answer it
 * from. The key's absence is the host's behaviour too (its `cross_layer` is
 * opt-in and `analyze` returns None without the bridge), so a caller that never
 * asks for it gets the object the differential harness has always compared.
 */
std::string ExplainToJson(const ExplainResult &r);

} // namespace policy_loop

#endif // POLICY_LOOP_PL_CONVERGE_H
