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

#ifndef POLICY_LOOP_PL_LOG_SOURCE_H
#define POLICY_LOOP_PL_LOG_SOURCE_H

#include <memory>
#include <string>

namespace policy_loop {

/*
 * Where the denial text comes from.
 *
 * Every acquisition path collapses to "hand me a byte string": which domain the
 * tool runs in, whether a socket is reachable, whether hilog is running -- all
 * of that uncertainty stops here, so the parser and the convergence engine
 * downstream are identical no matter how the log arrived. That is also what
 * makes the host/device differential meaningful: the device can be fed the very
 * same file the host read, taking the log source out of the comparison.
 *
 * `ReadAll` is budgeted because two of the sources are streams that never end.
 * /dev/kmsg reaches no EOF and never returns 0 bytes, and `hilog -x -t kmsg`
 * tails; a plain "read to EOF" would hang. A zero budget means unlimited, which
 * is right for a file and for stdin.
 */
struct ReadBudget {
    long long maxBytes = 0;     // 0 = unlimited
    long long maxMs = 0;        // 0 = unlimited, wall clock
};

class LogSource {
public:
    virtual ~LogSource() = default;

    // Reads the source into *out. Returns false and fills *err on failure.
    virtual bool ReadAll(std::string *out, std::string *err, const ReadBudget &budget) = 0;

    // Short machine tag for the report's `device.source`: file|stdin|cmd|kmsg.
    virtual std::string Tag() const = 0;

    // Human-readable origin, for the report header line.
    virtual std::string Describe() const = 0;

    // True when the source may silently drop records, so the reader should treat
    // the observed count as a lower bound. A regular file is complete; a kmsg or
    // hilog stream is subject to the kernel's printk rate limit.
    virtual bool IsSampled() const = 0;

    // --- follow mode ---------------------------------------------------
    // ReadAll is a snapshot: it opens, drains, closes. Following needs the
    // opposite shape -- one handle kept open across calls, so the first read
    // yields the backlog and every later read yields only what has arrived
    // since. A source that cannot do that (a file, a pipe) says so here and
    // the caller falls back to the snapshot path instead of silently
    // re-reporting the same records forever.
    virtual bool CanFollow() const { return false; }

    // Reads only what is new since the previous ReadNew on this object.
    // Returns true with *out possibly empty when nothing has arrived yet.
    virtual bool ReadNew(std::string *out, std::string *err, const ReadBudget &budget)
    {
        (void)out;
        (void)budget;
        *err = "source is not streamable";
        return false;
    }

    // True once the stream has ended of its own accord -- a followed command
    // exited. A follower must stop on this: an ended stream and an idle one
    // both read as "nothing new", so without it the loop would wait forever on
    // a producer that is already gone. /dev/kmsg never ends.
    virtual bool Eof() const { return false; }

    // How many times the source told us it had overwritten records we had not
    // read yet. /dev/kmsg does this by returning EPIPE (printk.c: "our last
    // seen message is gone, return error and reset"): it is not a failure but
    // a resync, since the kernel has already moved the read cursor to the
    // oldest record that survived. The records in between are simply lost, and
    // an unknown number of them, so this is a count of events and not of
    // records -- enough to say "this run did not see everything", which is all
    // a lower-bound claim needs.
    virtual long long Overruns() const { return 0; }
};

// path "-" or "" reads stdin.
std::unique_ptr<LogSource> MakeFileSource(const std::string &path);
std::unique_ptr<LogSource> MakeStdinSource();

// Runs `cmd` through /bin/sh and reads its stdout, e.g. "hilog -x -t kmsg".
std::unique_ptr<LogSource> MakeCommandSource(const std::string &cmd);

// Reads /dev/kmsg. Needs CAP_SYSLOG (or root) and is non-blocking, so the
// budget is what ends the read.
std::unique_ptr<LogSource> MakeKmsgSource();

} // namespace policy_loop

#endif // POLICY_LOOP_PL_LOG_SOURCE_H
