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

/*
 * denial_check -- converge `avc: denied` events against the policy index on the
 * device itself.
 *
 * Reads AVC denials from a log source, groups them by logical access, queries
 * the pre-exported policy index (PLI v1) and emits, per case, the same
 * classification, rationale and minimal patch text the host-side Python engine
 * produces. Never writes policy: the output is text for a human to review.
 *
 * Diagnostics go to stderr; stdout carries only the report, so the tool composes
 * in a pipeline. No hilog/selinux headers are pulled in -- the core stays on
 * libc/libc++/libm so it can run under any domain that can read its input file.
 */

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <getopt.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include "pl_avc_parser.h"
#include "pl_converge.h"
#include "pl_index.h"
#include "pl_log_source.h"
#include "pl_report.h"
#include "pl_sha1.h"
#include "pl_types.h"

namespace {

const char *kProgram = "denial_check";

void PrintUsage()
{
    std::fputs(
        "Usage: denial_check [options]\n"
        "\n"
        "Options:\n"
        "  -i, --index <file>    policy index (PLI v1, exported on the host)\n"
        "      --index-info      load the index, print its counters as JSON and\n"
        "                        exit. Use it to confirm the index arrived intact:\n"
        "                        the counters must equal the exporter's summary.\n"
        "      --query <file>    answer one policy query per line and print the\n"
        "                        verdicts as JSONL. Line format:\n"
        "                          <src>\\t<tgt>\\t<cls>\\t<perms>\\t<ioctlcmd>\n"
        "                        where <perms> is comma separated and a missing\n"
        "                        ioctlcmd is '-'. Used for the host/device query\n"
        "                        differential.\n"
        "      --converge        cluster the log and emit the convergence report\n"
        "                        as JSON. Needs --index and --log; the report is\n"
        "                        field-for-field the host engine's, so the two can\n"
        "                        be diffed directly. A `device` block of\n"
        "                        device-only facts (index revision, sampling loss,\n"
        "                        timings) is added alongside it, and the summary\n"
        "                        banner goes to stderr so stdout stays parseable.\n"
        "      --explain <line>  explain ONE `avc: denied` line: its root cause,\n"
        "                        what the policy says about it, and the minimal fix\n"
        "                        if there is one. Needs --index. Quote the line you\n"
        "                        copied out of hilog/dmesg. Nothing is applied --\n"
        "                        the output is advice. Exits 4 if <line> holds no\n"
        "                        denial.\n"
        "      --json            with --explain: print that answer as one JSON\n"
        "                        object instead of for reading\n"
        "      --case <file>     decide one already-split record per line and print\n"
        "                        the verdicts as JSONL. The fixed per-record API: a\n"
        "                        driver that reads its own logs splits them itself\n"
        "                        and sends records here, instead of asking the\n"
        "                        device for a finished report. Line format:\n"
        "                          <scontext>\\t<tcontext>\\t<tclass>\\t<perms>\\t\n"
        "                          <permissive>\\t<ioctlcmd>\\t<service>\n"
        "                        <perms> is comma separated in log order;\n"
        "                        <permissive> is permissive/enforcing/unknown; '-'\n"
        "                        means the field is absent. Needs --index.\n"
        "      --full            with --case: take the full pipeline for every\n"
        "                        record rather than settling the cheap cases first.\n"
        "                        The two paths word `why` differently, so a caller\n"
        "                        that needs report parity must not pass this.\n"
        "  -l, --log <file>      read denials from <file> ('-' or omitted: stdin)\n"
        "      --log-cmd <cmd>   read denials from the stdout of <cmd>, e.g.\n"
        "                        \"hilog -x -t kmsg\". Combined with --timeout-ms,\n"
        "                        since such a command usually tails rather than\n"
        "                        exits.\n"
        "      --kmsg            read /dev/kmsg (needs CAP_SYSLOG). Also needs\n"
        "                        --timeout-ms: the kernel never signals EOF there.\n"
        "      --timeout-ms <n>  stop reading a streaming source after <n> ms\n"
        "  -d, --dump-denials    parse only, and write one JSON object per record\n"
        "                        to stdout (JSONL, sorted keys). Used by the\n"
        "                        host/device differential harness: both sides emit\n"
        "                        the same shape, so `diff` is the comparison.\n"
        "      --follow          keep the source open and write each record the\n"
        "                        moment it lands, flushed, in --dump-denials' shape.\n"
        "                        This is the live mode: a reader polling the stream\n"
        "                        sees a denial while it is still the newest line.\n"
        "                        With --timeout-ms 0 it runs until killed.\n"
        "      --from-now        with --follow: drop the backlog the first read\n"
        "                        returns. Attaching to /dev/kmsg replays the whole\n"
        "                        ring buffer, so without this a watch that started a\n"
        "                        second ago reports hours of history.\n"
        "      --dedupe          with --follow: emit each fingerprint once. One\n"
        "                        daemon denied every 5s is one case, not 700. The\n"
        "                        count is reported on stderr.\n"
        "      --out <file>      with --follow: append the record stream to <file>\n"
        "                        instead of stdout. Needed when the process is a\n"
        "                        service, because init has no stdio redirection.\n"
        "      --guard           run as a service and follow the feature switch:\n"
        "                        while <dir>/guard.on holds '1', append to\n"
        "                        <dir>/live.jsonl; when it stops holding '1', end\n"
        "                        the session but keep running. Creates both files\n"
        "                        (0666) if the app has not, waits for <dir> to\n"
        "                        appear, and always starts a session on an empty\n"
        "                        file. Implies --from-now per session.\n"
        "      --dir <dir>       the app's files directory, for --guard\n"
        "  -s, --selftest        run the built-in fixed-vector self test and exit\n"
        "                        (requires no index and no log; use it to tell\n"
        "                        \"does not run\" apart from \"computes wrong\")\n"
        "  -v, --version         print the PLI/index revision this build speaks\n"
        "  -h, --help            show this help\n",
        stdout);
}

void PrintVersion()
{
    // The index revision is reported alongside the binary's, because a verdict
    // is only meaningful when the index and the firmware's compiled policy come
    // from the same sepolicy tree (see the `@src` line of the PLI file).
    std::fputs("denial_check 0.1 (PLI v1)\n", stdout);
}

// --------------------------------------------------------------------------
// Self test
// --------------------------------------------------------------------------

struct Sha1Vector {
    const char *input;
    const char *expected;
    const char *note;
};

// Fixed vectors generated on the host with Python's hashlib. They concentrate on
// the padding boundaries (54/55/56/57/63/64/65/119/120 bytes), which is where a
// hand-written SHA-1 goes wrong; the values are the published SHA-1 digests, so
// they are independent of this repository's Python.
const Sha1Vector kSha1Vectors[] = {
    {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "empty"},
    {"a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "1 byte"},
    {"aaa", "7e240de74fb1ed08fa08d38063f6a6a91462a815", "classic abc"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "b05d71c64979cb95fa74a33cdb31a40d258ae02e", "boundary: 54 (<56, single block)"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "c1c8bbdc22796e28c0e15163d20899b65621d65a", "boundary: 55 (length exactly fits)"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "c2db330f6083854c99d4b5bfb6e8f29f201be699", "boundary: 56 (forces a second block)"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "f08f24908d682555111be7ff6f004e78283d989a", "boundary: 57"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "03f09f5b158a7a8cdad920bddc29b81c18a551f5", "boundary: 63"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "0098ba824b5c16427bd7a1122a5a442a25ec644d", "boundary: 64 (exact block)"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "11655326c708d70319be2610e8a57d9a5b959d3b", "boundary: 65"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56", "boundary: 119"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "f34c1488385346a55709ba056ddd08280dd4c6d6", "boundary: 120 (second block start)"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "e61cfffe0d9195a525fc6cf06ca2d77119c24a40", "multi-block: 200"},
};

int SelfTestSha1()
{
    int failures = 0;
    for (const Sha1Vector &v : kSha1Vectors) {
        std::string got = policy_loop::Sha1Hex(std::string(v.input));
        if (got != v.expected) {
            std::fprintf(stderr, "selftest: sha1 FAIL  %s\n  expected %s\n  got      %s\n",
                         v.note, v.expected, got.c_str());
            ++failures;
        }
    }
    std::printf("selftest: sha1 %zu vectors, %d failure(s)\n",
                sizeof(kSha1Vectors) / sizeof(kSha1Vectors[0]), failures);
    return failures;
}

// --------------------------------------------------------------------------
// Self test: convergence vectors
// --------------------------------------------------------------------------

/*
 * A nine-rule policy and twenty-three denial lines, both small enough to read.
 *
 * The point of the pair is coverage of the *decisions*, not of the parser: the
 * differential harness against the host engine needs the device to work and a
 * log to work on, and on a fresh device neither is guaranteed. So the vectors
 * are chosen to land one case in every branch of the convergence pipeline --
 * each category, each classification, each guard that downgrades an automatic
 * patch to a human decision -- plus the malformed records that produce the
 * subtlest output: a missing scontext, a missing tclass, and a target context
 * that is a bare MLS level. Those three are the ones where the tool has to
 * render an absent field and still produce a patch line the verifier can rule
 * on, so they are exactly the cases a self test should pin.
 */
const char *const kSelfTestPli = R"PLI(PLI1
@rev 2
@src selftest.embedded gen=2026-09-10T00:00:00Z exporter=policy_loop/export/pli.py
@meta rules=9 allow=6 neverallow=2 allowxperm=1 neverallowxperm=0 types=13 attrs=2 classes=3 perms=6 known=13 skipped=0 hap_entries=0 hap_domains=0 hap_names=0 hap_apls=0 hap_debuggable=0 hap_skipped=0
@class chr_file 5
@class hdf_devmgr_class 1
@class samgr_class 3
@type app_service domain
@type audio_svc domain
@type default_service domain
@type dev_camera_file file_type
@type dev_null file_type
@type hdf_sensor_dev file_type
@type init domain
@type media_service domain
@type sa_audio_svc file_type
@type sa_binder file_type
@type sa_evil_svc file_type
@type sa_gap_svc file_type
@type unknown_domain domain
@attr domain
@attr file_type
@known app_service
@known audio_svc
@known default_service
@known dev_camera_file
@known dev_null
@known hdf_sensor_dev
@known init
@known media_service
@known sa_audio_svc
@known sa_binder
@known sa_evil_svc
@known sa_gap_svc
@known unknown_domain
@perm add
@perm get
@perm ioctl
@perm open
@perm read
@perm write
@rules 9
a chr_file init dev_null open,read,write
a chr_file media_service dev_camera_file open,read
n chr_file app_service dev_camera_file write
x chr_file media_service dev_camera_file ioctl:0x5401
a chr_file media_service dev_camera_file ioctl
a samgr_class media_service sa_audio_svc get
a samgr_class audio_svc sa_audio_svc add
a hdf_devmgr_class media_service hdf_sensor_dev get
n samgr_class media_service sa_evil_svc get
)PLI";

const char *const kSelfTestLog = R"LOG(audit: type=1400 audit(1700000000.1:1): avc:  denied  { read } for  pid=1 comm="init" scontext=u:r:init:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=1
audit: type=1400 audit(1700000000.2:2): avc:  denied  { read } for  pid=1 comm="init" scontext=u:r:init:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.3:3): avc:  denied  { write } for  pid=2 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.4:4): avc:  denied  { write } for  pid=3 comm="app_service" scontext=u:r:app_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file permissive=1
audit: type=1400 audit(1700000000.5:5): avc:  denied  { read } for  pid=4 comm="ghost" scontext=u:r:ghost_domain:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.6:6): avc:  denied  { ioctl } for  pid=5 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file ioctlcmd=0x5402 permissive=0
audit: type=1400 audit(1700000000.7:7): avc:  denied  { ioctl } for  pid=6 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_camera_file:s0 tclass=chr_file ioctlcmd=0x5401 permissive=0
audit: type=1400 audit(1700000000.8:8): avc:  denied  { read } for  pid=7 comm="default_service" scontext=u:r:default_service:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.9:9): avc:  denied  { call } for  pid=8 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:sa_binder:s0 tclass=binder permissive=0
audit: type=1400 audit(1700000000.10:10): avc:  denied  { read } for  pid=9 comm="media_service" tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.11:11): avc:  denied  { read } for  pid=10 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_null:s0 permissive=0
audit: type=1400 audit(1700000000.12:12): avc:  denied  { read } for  pid=11 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.13:13): avc:  denied  { read } for  pid=1 comm="init" scontext=u:r:init:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file permissive=1
audit: type=1400 audit(1700000000.14:14): avc:  denied  { read } for  pid=12 comm="media_service" scontext=u:r:media_service:s0 tcontext=s0 tclass=chr_file permissive=0
audit: type=1400 audit(1700000000.15:15): avc:  denied  { write } for  pid=13 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:dev_null:s0 tclass=chr_file
audit: type=1400 audit(1700000000.16:16): avc:  denied  { get } for  pid=14 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=audio_svc permissive=1
audit: type=1400 audit(1700000000.17:17): avc:  denied  { get } for  pid=15 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_hdf_service:s0 tclass=hdf_devmgr_class service=sensor_dev permissive=1
audit: type=1400 audit(1700000000.18:18): avc:  denied  { add } for  pid=16 comm="audio_svc" scontext=u:r:audio_svc:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=312 permissive=1
audit: type=1400 audit(1700000000.19:19): avc:  denied  { get find } for  pid=17 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=999 permissive=0
audit: type=1400 audit(1700000000.20:20): avc:  denied  { get open } for  pid=18 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=no_such_svc permissive=0
audit: type=1400 audit(1700000000.21:21): avc:  denied  { get } for  pid=19 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=chr_file service=audio_svc permissive=0
audit: type=1400 audit(1700000000.22:22): avc:  denied  { get write } for  pid=20 comm="media_service" scontext=u:r:media_service:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=evil_svc permissive=0
audit: type=1400 audit(1700000000.23:23): avc:  denied  { get } for  pid=21 comm="audio_svc" scontext=u:r:audio_svc:s0 tcontext=u:object_r:default_service:s0 tclass=samgr_class service=gap_svc permissive=0
)LOG";

/*
 * The expected outcome per cluster, one line each, in the order the clusters
 * appear (order of first appearance in the log).
 *
 * Generated by the *host* engine -- `python3 tools/gen_selftest_vectors.py` in
 * the policy_loop repo prints these lines -- so this is a frozen differential,
 * not a snapshot of this binary's
 * own behaviour (that script also emits the PLI and log above).
 * Regenerating the table against the C++ output would make the test
 * self-fulfilling and it would stop catching the divergences it exists to
 * catch; the digest must always come from the Python.
 *
 * Fields, pipe separated:
 *
 *   fp | count | src | tgt | cls | perms | category | classification |
 *   review | verify | why | patch
 *
 * An absent src/tgt/cls renders as the empty string here where the patch line
 * spells it `None`: the patch is the engine's literal suggestion text, so it
 * shows what a missing field does to the rule, while these columns show what it
 * does to the verdict.
 */
const char *const kSelfTestVectors[] = {
    "81d12e3a40e7|3|init|dev_null|chr_file|read|noise_or_already_allowed|NOISE_OR_ALREADY_FIXED|||策略已允许（历史/噪声）|",
    "71d6685de87b|1|media_service|dev_camera_file|chr_file|write|auto_repairable|MISSING_RULE|APPROVE|SUCCESS|最小权限补齐|allow media_service dev_camera_file:chr_file { write };",
    "798751551977|1|app_service|dev_camera_file|chr_file|write|needs_human|POTENTIAL_ESCALATION|||命中 neverallow 红线：禁止自动放权（转人工）|",
    "ff1a774b8c1a|1|ghost_domain|dev_null|chr_file|read|needs_human|MISSING_RULE|APPROVE|SUCCESS|主体/目标「ghost_domain」不在当前策略语料中（设备新增域、生成的数字 service 标签或标注异常），补丁无法落点验证，转人工|allow ghost_domain dev_null:chr_file { read };",
    "485a09a52db1|1|media_service|dev_camera_file|chr_file|ioctl|auto_repairable|XPERM_GAP|APPROVE|SUCCESS|最小权限补齐|allowxperm media_service dev_camera_file:chr_file ioctl { 0x5402 };",
    "c1e2002f0e99|1|media_service|dev_camera_file|chr_file|ioctl|needs_human|DOMAIN_OR_LABEL_MISMATCH|||策略已允许却被拒：疑似域/标签问题，非权限缺口|",
    "8331ae5e583b|1|default_service|dev_null|chr_file|read|auto_repairable|MISSING_RULE|APPROVE|SUCCESS|最小权限补齐|allow default_service dev_null:chr_file { read };",
    "f25011e16398|1|media_service|sa_binder|binder|call|needs_human|MISSING_RULE|APPROVE|SUCCESS|对象类「binder」不在策略任何规则中出现（疑为日志笔误），补丁无法落点验证，转人工|allow media_service sa_binder:binder { call };",
    "c9194a3bda82|1||dev_null|chr_file|read|needs_human|MISSING_RULE|APPROVE|FAILED|最小权限补齐|allow None dev_null:chr_file { read };",
    "a99b034e552d|1|media_service|dev_null||read|needs_human|MISSING_RULE|APPROVE|FAILED|最小权限补齐|allow media_service dev_null:None { read };",
    "43b4a87892c9|1|media_service|dev_null|chr_file|read|auto_repairable|MISSING_RULE|APPROVE|SUCCESS|最小权限补齐|allow media_service dev_null:chr_file { read };",
    "3ae84d5ebc05|1|media_service||chr_file|read|needs_human|MISSING_RULE|APPROVE|FAILED|最小权限补齐|allow media_service :chr_file { read };",
    "8666c016d1cb|1|media_service|dev_null|chr_file|write|auto_repairable|MISSING_RULE|APPROVE|SUCCESS|最小权限补齐|allow media_service dev_null:chr_file { write };",
    "376176f91046|1|media_service|default_service|samgr_class|get|noise_or_already_allowed|NOISE_OR_ALREADY_FIXED|||策略已允许（历史/噪声）|",
    "123fd1f538bf|1|media_service|default_hdf_service|hdf_devmgr_class|get|noise_or_already_allowed|NOISE_OR_ALREADY_FIXED|||策略已允许（历史/噪声）|",
    "083046588653|1|audio_svc|default_service|samgr_class|add|noise_or_already_allowed|NOISE_OR_ALREADY_FIXED|||策略已允许（历史/噪声）|",
    "75644f38bd50|1|media_service|default_service|samgr_class|get,find|needs_human|MISSING_RULE|APPROVE|SUCCESS|目标为 default_* 占位符（service 需映射到具体 sa_*/hdf 类型才能落规则），转人工|allow media_service default_service:samgr_class { find get };",
    "8eaa425c7f98|1|media_service|default_service|samgr_class|get,open|needs_human|MISSING_RULE|APPROVE|SUCCESS|目标为 default_* 占位符（service 需映射到具体 sa_*/hdf 类型才能落规则），转人工|allow media_service default_service:samgr_class { get open };",
    "1ac85dc76bb5|1|media_service|default_service|chr_file|get|needs_human|MISSING_RULE|APPROVE|SUCCESS|目标为 default_* 占位符（service 需映射到具体 sa_*/hdf 类型才能落规则），转人工|allow media_service default_service:chr_file { get };",
    "c078a0bca052|1|media_service|default_service|samgr_class|get,write|needs_human|POTENTIAL_ESCALATION|||命中 neverallow 红线：禁止自动放权（转人工）|",
    "33aa1b00e716|1|audio_svc|default_service|samgr_class|get|needs_human|MISSING_RULE|APPROVE|SUCCESS|目标为 default_* 占位符（service 需映射到具体 sa_*/hdf 类型才能落规则），转人工|allow audio_svc default_service:samgr_class { get };",
};

// One cluster's outcome as a single comparable line; the inverse of the comment
// above. Field order is fixed by kSelfTestVectors.
std::string ClusterDigest(const policy_loop::Cluster &cl)
{
    std::string perms;
    for (size_t i = 0; i < cl.perms.size(); ++i) {
        if (i != 0) {
            perms += ",";
        }
        perms += cl.perms[i];
    }
    return cl.fp + "|" + std::to_string(cl.count) + "|" + cl.src + "|" + cl.tgt + "|" +
           cl.cls + "|" + perms + "|" + cl.category + "|" + cl.classification + "|" +
           cl.reviewStatus + "|" + cl.verifyStatus + "|" + cl.why + "|" + cl.patch;
}

int SelfTestConverge()
{
    int failures = 0;
    const size_t want = sizeof(kSelfTestVectors) / sizeof(kSelfTestVectors[0]);

    std::string err;
    std::unique_ptr<policy_loop::PlIndex> index =
        policy_loop::PlIndex::LoadFromText(kSelfTestPli, &err);
    if (index == nullptr) {
        // Not a vector mismatch but a broken embedded policy: the vectors below
        // could never pass, so say so once instead of thirteen times.
        std::fprintf(stderr, "selftest: converge FAIL  embedded PLI did not load: %s\n",
                     err.c_str());
        return 1;
    }

    policy_loop::ConvergeReport report =
        policy_loop::Converge(policy_loop::ParseDenials(kSelfTestLog), index.get());
    if (report.clusters.size() != want) {
        std::fprintf(stderr, "selftest: converge FAIL  expected %zu clusters, got %zu\n",
                     want, report.clusters.size());
        ++failures;
    }

    size_t n = report.clusters.size() < want ? report.clusters.size() : want;
    for (size_t i = 0; i < n; ++i) {
        std::string got = ClusterDigest(report.clusters[i]);
        if (got != kSelfTestVectors[i]) {
            // Printed in full rather than field by field: the digest is what the
            // host engine was asked for, so the whole line is the unit that
            // either agrees or does not.
            std::fprintf(stderr, "selftest: converge FAIL  cluster %zu\n  expected %s\n  got      %s\n",
                         i, kSelfTestVectors[i], got.c_str());
            ++failures;
        }
    }
    std::printf("selftest: converge %zu vectors, %d failure(s)\n", want, failures);
    return failures;
}

/*
 * A neverallow is a per-permission assertion, and the vector table cannot show
 * that: every vector whose case hits a red line happens to request the very
 * permission the rule names, so the same table passes under a matcher that
 * ignores permissions entirely -- which is exactly the bug that was there.
 *
 * This is the paired form `selfcheck.py` uses on the host: each rule is probed
 * once with the permission it names (must hit) and once with a permission it
 * does not (must not). Only the second half can tell the two matchers apart, so
 * an assertion that just counts hits cannot replace it.
 */
int SelfTestNeverallowScope()
{
    int failures = 0;
    std::string err;
    std::unique_ptr<policy_loop::PlIndex> index =
        policy_loop::PlIndex::LoadFromText(kSelfTestPli, &err);
    if (index == nullptr) {
        std::fprintf(stderr, "selftest: neverallow FAIL  embedded PLI did not load: %s\n",
                     err.c_str());
        return 1;
    }

    // (src, tgt, cls, perm the rule names, perm it does not) -- the two rules in
    // the fixture, on two different object classes.
    struct Probe {
        const char *src;
        const char *tgt;
        const char *cls;
        const char *named;
        const char *other;
    };
    const Probe probes[] = {
        {"app_service", "dev_camera_file", "chr_file", "write", "read"},
        {"media_service", "sa_evil_svc", "samgr_class", "get", "add"},
    };

    for (const Probe &p : probes) {
        policy_loop::SymId src = index->FindSym(p.src);
        policy_loop::SymId tgt = index->FindSym(p.tgt);
        policy_loop::SymId cls = index->FindSym(p.cls);
        std::vector<const policy_loop::PlRule *> named;
        std::vector<const policy_loop::PlRule *> other;
        std::vector<policy_loop::SymId> namedIds{index->Intern(p.named)};
        std::vector<policy_loop::SymId> otherIds{index->Intern(p.other)};
        index->NeverallowRules(src, tgt, cls, namedIds, &named);
        index->NeverallowRules(src, tgt, cls, otherIds, &other);
        if (named.size() != 1 || !other.empty()) {
            std::fprintf(stderr,
                         "selftest: neverallow FAIL  %s -> %s:%s should be blocked for"
                         " {%s} and only for {%s}, got %zu and %zu\n",
                         p.src, p.tgt, p.cls, p.named, p.other, named.size(), other.size());
            ++failures;
        }
    }

    std::printf("selftest: neverallow %zu probes, %d failure(s)\n",
                sizeof(probes) / sizeof(probes[0]), failures);
    return failures;
}

int SelfTest()
{
    int failures = 0;
    failures += SelfTestSha1();
    failures += SelfTestConverge();
    failures += SelfTestNeverallowScope();
    if (failures == 0) {
        std::fputs("selftest: PASS\n", stdout);
    } else {
        std::fprintf(stderr, "selftest: FAIL (%d)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}

// --------------------------------------------------------------------------
// Input
// --------------------------------------------------------------------------

/*
 * Opens the configured log source and reads it whole.
 *
 * The acquisition options are mutually exclusive by construction, so the source
 * is chosen once here and every downstream mode sees the same bytes. The budget
 * only ever binds the streaming sources (/dev/kmsg, a tailable command) -- for a
 * file or stdin it is inert.
 */
std::unique_ptr<policy_loop::LogSource> MakeSource(const std::string &logPath,
                                                   const std::string &logCmd,
                                                   bool kmsg)
{
    if (kmsg) {
        return policy_loop::MakeKmsgSource();
    }
    if (!logCmd.empty()) {
        return policy_loop::MakeCommandSource(logCmd);
    }
    if (logPath.empty() || logPath == "-") {
        return policy_loop::MakeStdinSource();
    }
    return policy_loop::MakeFileSource(logPath);
}

bool ReadInput(const std::unique_ptr<policy_loop::LogSource> &source, std::string *out,
               std::string *err, const policy_loop::ReadBudget &budget)
{
    return source->ReadAll(out, err, budget);
}

// --------------------------------------------------------------------------
// --dump-denials
// --------------------------------------------------------------------------

/*
 * One JSON object per line, keys in sorted order and the default json.dumps
 * separators, so that the Python side emitting
 * `json.dumps(d, sort_keys=True, ensure_ascii=False)` produces a byte-identical
 * line for the same record. The harness then compares with `diff`, which also
 * names the offending record instead of just "the JSON differs".
 */
void DumpDenials(const std::vector<policy_loop::DenialRecord> &records)
{
    std::string line;
    for (const policy_loop::DenialRecord &rec : records) {
        line.clear();
        line += "{\"cls\": ";
        line += rec.tclass.present ? policy_loop::JsonString(rec.tclass.value) : "null";
        line += ", \"comm\": ";
        line += rec.comm.present ? policy_loop::JsonString(rec.comm.value) : "null";
        line += ", \"fp\": " + policy_loop::JsonString(policy_loop::Fingerprint(rec));
        line += ", \"ioctl\": ";
        line += rec.ioctlCmd.present ? policy_loop::JsonString(rec.ioctlCmd.value) : "null";
        line += ", \"name\": ";
        line += rec.name.present ? policy_loop::JsonString(rec.name.value) : "null";
        line += ", \"parameter\": ";
        line += rec.parameter.present ? policy_loop::JsonString(rec.parameter.value) : "null";
        line += ", \"path\": ";
        line += rec.path.present ? policy_loop::JsonString(rec.path.value) : "null";
        line += ", \"payload\": " + policy_loop::JsonString(policy_loop::FingerprintPayload(rec));
        line += ", \"permissive\": ";
        if (rec.permissive == policy_loop::Permissive::kUnknown) {
            line += "null";
        } else {
            line += (rec.permissive == policy_loop::Permissive::kPermissive) ? "true" : "false";
        }
        line += ", \"perms\": [";
        for (size_t i = 0; i < rec.permissions.size(); ++i) {
            if (i != 0) {
                line += ", ";
            }
            line += policy_loop::JsonString(rec.permissions[i]);
        }
        line += "], \"pid\": ";
        if (rec.hasPid) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%lld", rec.pid);
            line += buf;
        } else {
            line += "null";
        }
        line += ", \"raw\": " + policy_loop::JsonString(rec.raw);
        line += ", \"service\": ";
        line += rec.service.present ? policy_loop::JsonString(rec.service.value) : "null";
        line += ", \"src\": ";
        line += rec.source_domain.present ? policy_loop::JsonString(rec.source_domain.value) : "null";
        line += ", \"tgt\": ";
        line += rec.target_type.present ? policy_loop::JsonString(rec.target_type.value) : "null";
        line += "}\n";
        std::fwrite(line.data(), 1, line.size(), stdout);
    }
}

// --------------------------------------------------------------------------
// Index modes
// --------------------------------------------------------------------------

double NowMs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) * 1000.0 + static_cast<double>(ts.tv_nsec) / 1e6;
}

// --------------------------------------------------------------------------
// --follow
// --------------------------------------------------------------------------

/*
 * Longest a single read waits before handing back what it has.
 *
 * --kmsg never signals EOF, so a read only ends on its budget. Snapshot mode
 * spends the whole --timeout-ms in one call and is happy to; following cannot,
 * because the point is to surface a record while it is still news. Half a
 * second is short enough to feel immediate in a UI polling at 1 Hz and long
 * enough that an idle stream is not a spin loop.
 */
constexpr long long kFollowSliceMs = 500;

/*
 * Splits `*pending` on newlines, handing each complete line to `emit`.
 *
 * The tail after the last newline is an incomplete record -- /dev/kmsg writes
 * in chunks and a read can land mid-line -- so it stays in `pending` for the
 * next read to finish. Nothing is emitted for it: a half line parses into a
 * half record with fields that look absent rather than truncated, which is
 * exactly the wrong answer to hand a reader that is about to advise a fix.
 */
template <typename Emit>
void DrainLines(std::string *pending, Emit emit)
{
    size_t pos = 0;
    for (;;) {
        size_t nl = pending->find('\n', pos);
        if (nl == std::string::npos) {
            break;
        }
        emit(pending->substr(pos, nl - pos));
        pos = nl + 1;
    }
    pending->erase(0, pos);
}

/*
 * Reads the feature switch. Anything but a leading '1' is off, including a
 * missing file: a collector that ran because a file it could not read might
 * have said "on" would be reading the audit log without being asked to.
 */
bool SwitchIsOn(const std::string &path)
{
    FILE *f = std::fopen(path.c_str(), "r");
    if (f == nullptr) {
        return false;
    }
    char buf[8] = {0};
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    return n > 0 && buf[0] == '1';
}

/*
 * Creates the two files the app and this process share, if they are missing,
 * and makes them world-writable.
 *
 * Both steps are forced by the same policy fact, which is worth stating because
 * it is the opposite of what a sandbox usually implies: the app's own domain
 * holds `debug_hap_data_file:file { read write open }` and **no permission at
 * all on the dir class**. So the app can rewrite a file that exists and can
 * never create one, and it cannot chmod what root created. A freshly installed
 * app has an empty sandbox, so if this process does not lay the files down
 * first, the switch fails with "cannot write" and the feature looks broken for
 * a reason that has nothing to do with the feature.
 */
void EnsureSwitchFiles(const std::string &sw, const std::string &live)
{
    if (::access(sw.c_str(), F_OK) != 0) {
        FILE *f = std::fopen(sw.c_str(), "w");
        if (f != nullptr) {
            std::fputs("0\n", f);
            std::fclose(f);
        }
    }
    if (::access(live.c_str(), F_OK) != 0) {
        FILE *f = std::fopen(live.c_str(), "w");
        if (f != nullptr) {
            std::fclose(f);
        }
    }
    ::chmod(sw.c_str(), 0666);
    ::chmod(live.c_str(), 0666);
}

/*
 * Streams a live source, writing one JSON object per record as it arrives.
 *
 * The shape of each line is DumpDenials' exactly, so a follower can hand the
 * stream to the same reader that consumes --dump-denials and a `diff` of the
 * two still means something. What differs is timing: every batch is flushed,
 * because a downstream reader that polls a file (or a pipe) must see a record
 * while it is still the newest thing in the log. The C stdio buffer would
 * otherwise hold hundreds of records and release them together at exit, which
 * is precisely the behaviour that made this mode necessary.
 *
 * Two filters exist because "every record" and "what a human needs to be told"
 * are not the same set, and a popup driver wants the second:
 *
 *   --from-now   drop the backlog the first read returns. Attaching to kmsg
 *                replays the whole ring buffer, so without this a watch that
 *                started a second ago immediately reports hours of history.
 *   --dedupe     emit a fingerprint once. A broken daemon denied every 5s is
 *                one problem, not 700; the count is kept and reported on
 *                stderr so the suppression is visible rather than silent.
 *
 * Both default off: the unfiltered stream is the honest one, and a caller that
 * wants a digest of it should ask.
 */
int FollowMode(const std::unique_ptr<policy_loop::LogSource> &source, long long timeoutMs,
               bool dedupe, bool fromNow, const std::string &outPath = std::string(),
               const std::string &switchPath = std::string())
{
    if (!source->CanFollow()) {
        std::fprintf(stderr,
                     "%s: --follow needs a streaming source; %s is a snapshot. "
                     "Use --kmsg, or --log-cmd with a command that tails.\n",
                     kProgram, source->Describe().c_str());
        return 2;
    }

    // A service started by init has no shell to redirect its stdout, and OHOS
    // init's cfg has no stdio redirection to ask for, so the stream has to
    // reach its file by this process's own hand. Everything below still writes
    // to stdout; this only points stdout at the file first.
    if (!outPath.empty()) {
        if (std::freopen(outPath.c_str(), "a", stdout) == nullptr) {
            std::fprintf(stderr, "%s: cannot open %s for append\n", kProgram, outPath.c_str());
            return 1;
        }
    }

    double deadline = (timeoutMs > 0) ? NowMs() + static_cast<double>(timeoutMs) : 0.0;
    std::string pending;
    std::unordered_set<std::string> seen;
    long long emitted = 0;
    long long suppressed = 0;
    long long dropped = 0;
    bool draining = fromNow;

    // The banner goes to stderr so stdout stays a pure record stream.
    std::fprintf(stderr, "%s: following %s (slice %lldms%s%s)\n", kProgram, source->Describe().c_str(),
                 kFollowSliceMs, dedupe ? ", dedupe" : "", fromNow ? ", from-now" : "");

    for (;;) {
        // A session ends when the operator turns the feature off. Checked once
        // per slice instead of through a signal or a second thread: the read
        // budget is already half a second, which is the same latency the UI
        // polling this file has, so a heavier mechanism would buy nothing.
        if (!switchPath.empty() && !SwitchIsOn(switchPath)) {
            std::fprintf(stderr, "%s: switch went off\n", kProgram);
            break;
        }

        long long slice = kFollowSliceMs;
        if (deadline > 0) {
            long long left = static_cast<long long>(deadline - NowMs());
            if (left <= 0) {
                break;
            }
            if (left < slice) {
                slice = left;
            }
        }

        policy_loop::ReadBudget budget;
        budget.maxMs = slice;

        std::string chunk;
        std::string err;
        if (!source->ReadNew(&chunk, &err, budget)) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            std::fflush(stdout);
            return 1;
        }
        pending += chunk;
        bool ended = source->Eof();

        DrainLines(&pending, [&](const std::string &line) {
            std::vector<policy_loop::DenialRecord> recs = policy_loop::ParseDenials(line);
            if (recs.empty()) {
                return;         // not an avc line: the ring buffer carries everything
            }
            if (draining) {
                dropped += static_cast<long long>(recs.size());
                return;
            }
            std::vector<policy_loop::DenialRecord> fresh;
            for (const policy_loop::DenialRecord &rec : recs) {
                if (dedupe && !seen.insert(policy_loop::Fingerprint(rec)).second) {
                    ++suppressed;
                    continue;
                }
                fresh.push_back(rec);
            }
            if (!fresh.empty()) {
                DumpDenials(fresh);
                emitted += static_cast<long long>(fresh.size());
            }
        });

        if (draining) {
            // The first read is the only one that replays; everything it held is
            // history, so the switch flips once it is done.
            draining = false;
        }
        std::fflush(stdout);

        if (ended) {
            // The producer is gone. Waiting out the rest of the budget would
            // mean sitting on a stream that cannot produce another record.
            // Any partial line here is truncated by the producer's death, so
            // it is reported rather than parsed.
            if (!pending.empty()) {
                std::fprintf(stderr, "%s: %zu trailing bytes after the stream ended: not a record\n",
                             kProgram, pending.size());
            }
            break;
        }
        if (deadline > 0 && NowMs() >= deadline) {
            break;
        }
    }

    // A trailing partial line is not a record and is deliberately not emitted;
    // saying so beats a stream that ends on a line no reader can parse.
    std::fprintf(stderr, "%s: followed %s for %lldms: %lld emitted, %lld suppressed, %lld backlog dropped\n",
                 kProgram, source->Describe().c_str(), timeoutMs, emitted, suppressed, dropped);
    if (source->Overruns() > 0) {
        // A follower that silently lost records would report a quiet system at
        // exactly the moment the log was too busy to keep up with.
        std::fprintf(stderr,
                     "%s: %lld ring overrun(s): records were overwritten before they could be read\n",
                     kProgram, source->Overruns());
    }
    std::fflush(stdout);
    return 0;
}

/*
 * Runs the collector the way a service runs: one long-lived process that opens
 * a fresh session every time the operator turns the feature on.
 *
 * Why this is in the binary and not a shell wrapper around it. OHOS init can
 * start a process, but the domain a service lands in comes from the `secon`
 * field of its cfg, and `sh /system/bin/pl_guard.sh` would ask for `secon` on
 * the *shell* -- putting a script that runs `ls`, `date` and `chmod` into the
 * same domain as a collector whose whole job needs two permissions, and handing
 * the collector the shell's entire permission set to get them. So the switch
 * polling, the file creation and the output redirection are the binary's job,
 * and the domain stays small enough to read in one sitting.
 *
 * This replaces device/board/pl_guard.sh for the service form. The script is
 * kept for the demo form, where everything runs under `su`.
 */
int GuardMode(const std::string &logPath, const std::string &logCmd, bool kmsg,
              bool dedupe, const std::string &dir)
{
    const std::string sw = dir + "/guard.on";
    const std::string live = dir + "/live.jsonl";

    std::fprintf(stderr, "%s: guard watching %s\n", kProgram, dir.c_str());

    for (;;) {
        struct stat st;
        if (::stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
            // The app may not be installed yet, and at boot this service may
            // well start first. A service that exited here would need a reboot
            // to come back; waiting costs one stat a second.
            sleep(1);
            continue;
        }
        EnsureSwitchFiles(sw, live);

        if (!SwitchIsOn(sw)) {
            sleep(1);
            continue;
        }

        // A session opens on an empty file. The operator asked for "what
        // happens from now on", and a list that opens with the previous
        // session's denials is the one thing that would make the popup
        // untrustworthy -- the reader could not tell new from remembered.
        FILE *f = std::fopen(live.c_str(), "w");
        if (f != nullptr) {
            std::fclose(f);
        }
        ::chmod(live.c_str(), 0666);
        std::fprintf(stderr, "%s: session start -> %s\n", kProgram, live.c_str());

        // timeoutMs 0: the switch ends the session, not a clock.
        // fromNow true: attaching to /dev/kmsg replays the whole ring buffer,
        // and that backlog is not what "since I turned this on" means.
        FollowMode(MakeSource(logPath, logCmd, kmsg), 0, dedupe, true, live, sw);
    }
}

int IndexInfo(const std::string &indexPath)
{
    double start = NowMs();
    std::string err;
    std::unique_ptr<policy_loop::PlIndex> index = policy_loop::PlIndex::LoadFile(indexPath, &err);
    if (index == nullptr) {
        std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
        return 3;
    }
    double loadMs = NowMs() - start;

    const policy_loop::IndexMeta &meta = index->meta();
    std::printf("{\"allow\": %lld, \"allowxperm\": %lld, \"attrs\": %lld, \"classes\": %lld, "
                "\"known\": %lld, \"load_ms\": %.1f, \"neverallow\": %lld, "
                "\"neverallowxperm\": %lld, \"perms\": %lld, \"rev\": %s, \"rules\": %lld, "
                "\"skipped\": %lld, \"source\": %s, \"types\": %lld}\n",
                meta.allow, meta.allowxperm, meta.attrs, meta.classes,
                meta.known, loadMs, meta.neverallow, meta.neverallowxperm,
                meta.perms, policy_loop::JsonString(index->rev()).c_str(), meta.rules,
                meta.skipped, policy_loop::JsonString(meta.source).c_str(), meta.types);
    return 0;
}

/*
 * One query per line: src \t tgt \t cls \t perms \t ioctlcmd
 *
 * Emits a JSON object per line with the same field set the Python side
 * produces, so the harness compares with a line diff.
 */
int QueryBatch(policy_loop::PlIndex *index, const std::string &text)
{
    std::string out;
    size_t lineNo = 0;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = (nl == std::string::npos) ? text.substr(pos)
                                                     : text.substr(pos, nl - pos);
        bool last = (nl == std::string::npos);
        pos = last ? text.size() + 1 : nl + 1;
        if (line.empty()) {
            continue;
        }
        ++lineNo;

        std::vector<std::string> f;
        size_t start = 0;
        while (true) {
            size_t tab = line.find('\t', start);
            if (tab == std::string::npos) {
                f.push_back(line.substr(start));
                break;
            }
            f.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        if (f.size() != 5) {
            std::fprintf(stderr, "%s: query line %zu has %zu fields, expected 5\n",
                         kProgram, lineNo, f.size());
            return 2;
        }

        policy_loop::SymId src = index->FindSym(f[0]);
        policy_loop::SymId tgt = index->FindSym(f[1]);
        policy_loop::SymId cls = index->FindSym(f[2]);
        policy_loop::SymId cmd = (f[4] == "-") ? policy_loop::kNoSym : index->FindSym(f[4]);

        // Requested permissions are *interned*, not looked up. A requested name
        // the policy never mentions still has to be carried through: if a
        // wildcard allow (empty permission set) matches, Python's has_access
        // folds the requested names in verbatim -- including ones that name
        // nothing -- and so reports them granted. Dropping unknown names here
        // would silently answer "allowed" for a request the host calls denied.
        std::vector<policy_loop::SymId> perms;
        size_t pstart = 0;
        while (!f[3].empty()) {
            size_t comma = f[3].find(',', pstart);
            std::string name = (comma == std::string::npos) ? f[3].substr(pstart)
                                                            : f[3].substr(pstart, comma - pstart);
            if (!name.empty()) {
                perms.push_back(index->Intern(name));
            }
            if (comma == std::string::npos) {
                break;
            }
            pstart = comma + 1;
        }
        std::sort(perms.begin(), perms.end());
        perms.erase(std::unique(perms.begin(), perms.end()), perms.end());

        std::vector<policy_loop::SymId> granted;
        bool allowed = index->HasAccess(src, tgt, cls, perms, &granted);
        policy_loop::IoctlVerdict ioctl = index->IoctlAllowed(src, tgt, cls, cmd);
        std::vector<const policy_loop::PlRule *> neverallow;
        index->NeverallowRules(src, tgt, cls, perms, &neverallow);

        // Emitted in name order, not symbol-id order: ids reflect interning
        // order, which is an implementation detail the Python side cannot know.
        std::vector<std::string> grantedNames;
        grantedNames.reserve(granted.size());
        for (policy_loop::SymId id : granted) {
            grantedNames.push_back(index->symName(id));
        }
        std::sort(grantedNames.begin(), grantedNames.end());

        out.clear();
        out += "{\"allowed\": ";
        out += allowed ? "true" : "false";
        out += ", \"granted\": [";
        for (size_t i = 0; i < grantedNames.size(); ++i) {
            if (i != 0) {
                out += ", ";
            }
            out += policy_loop::JsonString(grantedNames[i]);
        }
        out += "], \"ioctl_allowed\": ";
        out += ioctl.allowed ? "true" : "false";
        out += ", \"ioctl_reason\": " + policy_loop::JsonString(ioctl.reason);
        out += ", \"neverallow\": " + std::to_string(neverallow.size());
        out += "}\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
    }
    return 0;
}

// Newline count. A trailing partial line still counts: the parser would take it
// as a record, and a header that disagreed with the parser about how much input
// there was would be worse than no header.
long long CountLines(const std::string &text)
{
    long long lines = 0;
    for (char c : text) {
        if (c == '\n') {
            ++lines;
        }
    }
    if (!text.empty() && text.back() != '\n') {
        ++lines;
    }
    return lines;
}

/*
 * The whole convergence report for one log, as JSON on stdout.
 *
 * The log is read as a byte string and handed to the same parser the rest of
 * the tool uses, so a device run and a host run over the same file are directly
 * comparable -- which is the point: the report is the artifact the two sides
 * have to agree on.
 *
 * The report body is the host engine's, field for field. The `device` block
 * appended to it is the opposite: facts only this side can know. The banner
 * goes to stderr so that stdout stays one parseable document.
 */
int ConvergeReportMode(policy_loop::PlIndex *index, const std::string &text,
                       const policy_loop::LogSource &source, double loadMs)
{
    double start = NowMs();
    policy_loop::ConvergeReport report =
        policy_loop::Converge(policy_loop::ParseDenials(text), index);
    double queryMs = NowMs() - start;

    policy_loop::DeviceFacts facts;
    facts.indexRev = index->rev();
    facts.rulesLoaded = index->meta().rules;
    facts.skipped = index->meta().skipped;
    facts.source = source.Tag();
    facts.sourceDesc = source.Describe();
    facts.lines = CountLines(text);
    facts.observedDenials = report.totalDenials;
    facts.suppressedEstimate = policy_loop::CountSuppressed(text);
    facts.sampled = source.IsSampled();
    facts.overruns = source.Overruns();
    facts.loadMs = loadMs;
    facts.queryMs = queryMs;
    policy_loop::WarnIncompleteIndex(&facts);

    std::fprintf(stderr, "%s\n", policy_loop::HeaderLine(facts).c_str());
    std::string out = policy_loop::WithDeviceBlock(policy_loop::ReportToJson(report), facts);
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}

// --------------------------------------------------------------------------
// --explain
// --------------------------------------------------------------------------

std::string JoinSpaces(const std::vector<std::string> &v)
{
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i != 0) {
            out += ' ';
        }
        out += v[i];
    }
    return out;
}

/*
 * One denial, answered for whoever pasted it.
 *
 * The labels are Chinese because the explanation is: `security_agent._HUMAN`
 * speaks Chinese -- it is the wording a developer reads -- and a Chinese
 * paragraph under English labels reads as two tools stapled together. The
 * machine-facing half is `--json`, which keeps English keys so the differential
 * harness can compare it against the host's.
 *
 * The 访问 line echoes what the log asked for, not what the patch grants. The two
 * differ exactly when the denial is a fine-grained gap rather than a missing
 * rule, which is the distinction the 说明 paragraph exists to draw -- so showing
 * the request here and the patch below is the point, not a redundancy.
 */
int ExplainMode(policy_loop::PlIndex *index, const std::string &line, bool asJson)
{
    policy_loop::ExplainResult r = policy_loop::ExplainDenial(line, index);
    if (!r.parsed) {
        // "That is not a denial" is an answer, not a failure: the line was
        // copied out of a log window, and picking the wrong one is easy.
        std::fprintf(stderr,
                     "%s: no `avc: denied` record in the given line. Pass exactly "
                     "one log line, in quotes.\n",
                     kProgram);
        return 4;
    }
    if (asJson) {
        std::string out = policy_loop::ExplainToJson(r);
        std::fwrite(out.data(), 1, out.size(), stdout);
        return 0;
    }

    std::printf("分类  %s\n", r.classification.c_str());
    std::printf("访问  %s -> %s:%s { %s }\n", r.src.c_str(), r.tgt.c_str(),
                r.cls.c_str(), JoinSpaces(r.requested).c_str());
    std::printf("说明  %s\n", r.explanation.c_str());
    std::printf("建议  %s\n", r.recommendedTitle.c_str());
    // Review/verify describe a patch's fate, so they are only meaningful beside
    // one. Without a patch the recommendation above already says what to do.
    if (!r.patch.empty()) {
        std::printf("补丁  %s\n", r.patch.c_str());
        std::printf("评审  %s\n", r.reviewStatus.c_str());
        std::printf("验证  %s\n", r.verifyStatus.c_str());
    }
    return 0;
}

/*
 * The per-record shell: one already-split record in, one verdict out.
 *
 * This is the fixed API a host-side driver drives when it wants to walk the
 * cases itself rather than ask the device for a finished report. The split is
 * the point: the host owns line handling -- it may be reading hilog, a
 * hisysevent stream, or a log the device cannot reach -- and the device owns
 * what the policy says about a record. So nothing here parses an `avc: denied`
 * line; a record arrives with its fields already separated, which also lets a
 * caller hand over a record that never was a log line at all.
 *
 * Line format, tab separated, all seven fields required:
 *   <scontext> <tcontext> <tclass> <perms> <permissive> <ioctlcmd> <service>
 * <perms> is comma separated in log order. `-` means "this field is absent" --
 * the same sentinel --query uses -- and it is what keeps a record with no
 * tclass apart from one whose tclass is the empty string, since the verdict
 * renders those differently ("None" versus "").
 *
 * Output is JSONL, one object per input line, keys sorted: the shape contract
 * --dump-denials and --explain --json already follow.
 */
int CaseMode(policy_loop::PlIndex *index, const std::string &text,
             policy_loop::CasePath path)
{
    std::string out;
    size_t lineNo = 0;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = (nl == std::string::npos) ? text.substr(pos)
                                                     : text.substr(pos, nl - pos);
        bool last = (nl == std::string::npos);
        pos = last ? text.size() + 1 : nl + 1;
        if (line.empty()) {
            continue;
        }
        ++lineNo;

        std::vector<std::string> f;
        size_t start = 0;
        while (true) {
            size_t tab = line.find('\t', start);
            if (tab == std::string::npos) {
                f.push_back(line.substr(start));
                break;
            }
            f.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        if (f.size() != 7) {
            std::fprintf(stderr, "%s: case line %zu has %zu fields, expected 7\n",
                         kProgram, lineNo, f.size());
            return 2;
        }

        policy_loop::DenialRecord rec;
        // A record the shell built rather than parsed has no source line; the
        // decision path never reads it, so an empty one is honest here. The
        // same goes for comm/pid/path/name/parameter, which only the parser and
        // the report's sample text use.
        auto setOpt = [](policy_loop::OptStr *dst, const std::string &field) {
            if (field != "-") {
                dst->value = field;
                dst->present = true;
            }
        };
        setOpt(&rec.source_domain, f[0]);
        setOpt(&rec.target_type, f[1]);
        setOpt(&rec.tclass, f[2]);

        if (f[3] != "-" && !f[3].empty()) {
            size_t pstart = 0;
            while (true) {
                size_t comma = f[3].find(',', pstart);
                std::string name = (comma == std::string::npos)
                                       ? f[3].substr(pstart)
                                       : f[3].substr(pstart, comma - pstart);
                if (!name.empty()) {
                    rec.permissions.push_back(name);
                }
                if (comma == std::string::npos) {
                    break;
                }
                pstart = comma + 1;
            }
        }

        // Log order is preserved: ExplainCase sorts where Python sorts, and the
        // fingerprint that depends on this order is computed downstream.
        if (f[4] == "permissive") {
            rec.permissive = policy_loop::Permissive::kPermissive;
        } else if (f[4] == "enforcing") {
            rec.permissive = policy_loop::Permissive::kEnforcing;
        } else {
            rec.permissive = policy_loop::Permissive::kUnknown;
        }
        setOpt(&rec.ioctlCmd, f[5]);
        setOpt(&rec.service, f[6]);

        policy_loop::CaseVerdict verdict = policy_loop::ExplainCase(rec, index, path);
        // The guards are what a per-record consumer actually needs: not just
        // "here is the rule that would close the gap" but "and here is why you
        // must not apply it unattended". The report applies them, so a record
        // answered here has to carry the same judgement or the two drift.
        policy_loop::ApplyGuards(rec, index, &verdict);
        out += policy_loop::CaseVerdictToJson(verdict);
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}

} // namespace

namespace {

enum LongOnly {
    kOptIndexInfo = 1000,
    kOptQuery,
    kOptConverge,
    kOptLogCmd,
    kOptKmsg,
    kOptTimeoutMs,
    kOptExplain,
    kOptJson,
    kOptCase,
    kOptFull,
    kOptFollow,
    kOptDedupe,
    kOptFromNow,
    kOptOut,
    kOptGuard,
    kOptDir,
};

} // namespace

int main(int argc, char *argv[])
{
    static const struct option kOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {"selftest", no_argument, nullptr, 's'},
        {"log", required_argument, nullptr, 'l'},
        {"dump-denials", no_argument, nullptr, 'd'},
        {"index", required_argument, nullptr, 'i'},
        {"index-info", no_argument, nullptr, kOptIndexInfo},
        {"query", required_argument, nullptr, kOptQuery},
        {"converge", no_argument, nullptr, kOptConverge},
        {"log-cmd", required_argument, nullptr, kOptLogCmd},
        {"kmsg", no_argument, nullptr, kOptKmsg},
        {"timeout-ms", required_argument, nullptr, kOptTimeoutMs},
        {"explain", required_argument, nullptr, kOptExplain},
        {"json", no_argument, nullptr, kOptJson},
        {"case", required_argument, nullptr, kOptCase},
        {"full", no_argument, nullptr, kOptFull},
        {"follow", no_argument, nullptr, kOptFollow},
        {"dedupe", no_argument, nullptr, kOptDedupe},
        {"from-now", no_argument, nullptr, kOptFromNow},
        {"out", required_argument, nullptr, kOptOut},
        {"guard", no_argument, nullptr, kOptGuard},
        {"dir", required_argument, nullptr, kOptDir},
        {nullptr, no_argument, nullptr, 0},
    };

    if (argc == 1) {
        PrintUsage();
        return 0;
    }

    std::string logPath;
    std::string indexPath;
    std::string queryPath;
    std::string logCmd;
    std::string explainLine;
    std::string casePath;
    bool kmsg = false;
    long long timeoutMs = 0;
    bool dumpDenials = false;
    bool indexInfo = false;
    bool converge = false;
    bool explain = false;
    bool asJson = false;
    bool full = false;
    bool follow = false;
    bool dedupe = false;
    bool fromNow = false;
    std::string outPath;
    std::string guardDir;
    bool guard = false;

    int para = 0;
    while ((para = getopt_long(argc, argv, "hvsl:di:", kOptions, nullptr)) != -1) {
        switch (para) {
            case 'h':
                PrintUsage();
                return 0;
            case 'v':
                PrintVersion();
                return 0;
            case 's':
                return SelfTest();
            case 'l':
                logPath = optarg;
                break;
            case 'd':
                dumpDenials = true;
                break;
            case 'i':
                indexPath = optarg;
                break;
            case kOptIndexInfo:
                indexInfo = true;
                break;
            case kOptQuery:
                queryPath = optarg;
                break;
            case kOptConverge:
                converge = true;
                break;
            case kOptLogCmd:
                logCmd = optarg;
                break;
            case kOptKmsg:
                kmsg = true;
                break;
            case kOptTimeoutMs:
                timeoutMs = std::strtoll(optarg, nullptr, 10);
                if (timeoutMs < 0) {
                    std::fprintf(stderr, "%s: --timeout-ms must not be negative\n", kProgram);
                    return 2;
                }
                break;
            case kOptExplain:
                explainLine = optarg;
                explain = true;
                break;
            case kOptJson:
                asJson = true;
                break;
            case kOptCase:
                casePath = optarg;
                break;
            case kOptFull:
                full = true;
                break;
            case kOptFollow:
                follow = true;
                break;
            case kOptDedupe:
                dedupe = true;
                break;
            case kOptFromNow:
                fromNow = true;
                break;
            case kOptOut:
                outPath = optarg;
                break;
            case kOptGuard:
                guard = true;
                break;
            case kOptDir:
                guardDir = optarg;
                break;
            default:
                std::fprintf(stderr, "Try '%s -h' for more information.\n", kProgram);
                return 2;
        }
    }

    if (asJson && !explain) {
        std::fprintf(stderr, "%s: --json only applies to --explain\n", kProgram);
        return 2;
    }
    if (full && casePath.empty()) {
        std::fprintf(stderr, "%s: --full only applies to --case\n", kProgram);
        return 2;
    }
    // --guard runs a --follow session internally, so a caller writing the
    // production command line naturally reaches for --dedupe -- and GuardMode
    // does honour it. Rejecting it here is what actually shipped: the init cfg
    // said "--guard --dedupe --kmsg", validation exited 2, and because init
    // sends a service's stderr to /dev/null the service died on every boot
    // without leaving a trace. The mistake only surfaced when the production
    // command line was finally run as a whole, in the pre-reboot rehearsal.
    //
    // --from-now is allowed through too rather than special-cased: GuardMode
    // hardcodes from-now (a session means "from the moment you switched this
    // on"), so the flag is redundant there, not contradictory.
    if ((dedupe || fromNow) && !follow && !guard) {
        std::fprintf(stderr, "%s: --dedupe and --from-now only apply to --follow or --guard\n", kProgram);
        return 2;
    }
    if (follow && dumpDenials) {
        // Both write the record stream to stdout; taking both would emit it twice.
        std::fprintf(stderr, "%s: --follow and --dump-denials are mutually exclusive\n", kProgram);
        return 2;
    }
    if (guard && guardDir.empty()) {
        std::fprintf(stderr, "%s: --guard needs --dir <the app's files directory>\n", kProgram);
        return 2;
    }
    if (guard && !outPath.empty()) {
        // --guard owns both files inside --dir; a second output path would be a
        // second stream to keep in step with the switch for no reason.
        std::fprintf(stderr, "%s: --guard writes live.jsonl inside --dir; --out is for plain --follow\n",
                     kProgram);
        return 2;
    }
    if (indexInfo || !queryPath.empty() || converge || explain || !casePath.empty()) {
        if (indexPath.empty()) {
            std::fprintf(stderr,
                         "%s: --index-info, --query, --converge, --case and --explain "
                         "need --index <file>\n",
                         kProgram);
            return 2;
        }
    }
    if (indexInfo) {
        return IndexInfo(indexPath);
    }

    if (!casePath.empty()) {
        std::string err;
        std::unique_ptr<policy_loop::PlIndex> index = policy_loop::PlIndex::LoadFile(indexPath, &err);
        if (index == nullptr) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            return 3;
        }
        std::string text;
        std::string err2;
        if (!ReadInput(policy_loop::MakeFileSource(casePath), &text, &err2,
                       policy_loop::ReadBudget())) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err2.c_str());
            return 1;
        }
        policy_loop::CasePath path = full ? policy_loop::CasePath::kFullPipeline
                                          : policy_loop::CasePath::kQuickThenPipeline;
        return CaseMode(index.get(), text, path);
    }

    if (explain) {
        std::string err;
        std::unique_ptr<policy_loop::PlIndex> index = policy_loop::PlIndex::LoadFile(indexPath, &err);
        if (index == nullptr) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            return 3;
        }
        return ExplainMode(index.get(), explainLine, asJson);
    }

    // One log source, chosen once. Silently preferring one over another would
    // make "which log did this verdict come from?" unanswerable at exactly the
    // moment it matters.
    int sources = (!logCmd.empty() ? 1 : 0) + (kmsg ? 1 : 0);
    if (sources > 1) {
        std::fprintf(stderr, "%s: --log-cmd and --kmsg are mutually exclusive\n", kProgram);
        return 2;
    }
    if (follow && converge) {
        // One streams records as they land, the other reports a settled
        // cluster of them; a stream has no settled point to report.
        std::fprintf(stderr, "%s: --follow and --converge are mutually exclusive\n", kProgram);
        return 2;
    }

    if (guard) {
        return GuardMode(logPath, logCmd, kmsg, dedupe, guardDir);
    }

    if (follow) {
        return FollowMode(MakeSource(logPath, logCmd, kmsg), timeoutMs, dedupe, fromNow, outPath);
    }

    if (converge) {
        std::string err;
        double start = NowMs();
        std::unique_ptr<policy_loop::PlIndex> index = policy_loop::PlIndex::LoadFile(indexPath, &err);
        if (index == nullptr) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            return 3;
        }
        double loadMs = NowMs() - start;

        std::unique_ptr<policy_loop::LogSource> source = MakeSource(logPath, logCmd, kmsg);
        std::string text;
        policy_loop::ReadBudget budget;
        budget.maxMs = timeoutMs;
        if (!ReadInput(source, &text, &err, budget)) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            return 1;
        }
        return ConvergeReportMode(index.get(), text, *source, loadMs);
    }

    if (!queryPath.empty()) {
        std::string err;
        std::unique_ptr<policy_loop::PlIndex> index = policy_loop::PlIndex::LoadFile(indexPath, &err);
        if (index == nullptr) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            return 3;
        }
        std::string text;
        if (!ReadInput(policy_loop::MakeFileSource(queryPath), &text, &err,
                       policy_loop::ReadBudget())) {
            std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
            return 1;
        }
        return QueryBatch(index.get(), text);
    }

    if (!dumpDenials) {
        PrintUsage();
        return 2;
    }

    std::string text;
    std::string err;
    policy_loop::ReadBudget budget;
    budget.maxMs = timeoutMs;
    if (!ReadInput(MakeSource(logPath, logCmd, kmsg), &text, &err, budget)) {
        std::fprintf(stderr, "%s: %s\n", kProgram, err.c_str());
        return 1;
    }
    DumpDenials(policy_loop::ParseDenials(text));
    return 0;
}
