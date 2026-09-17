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

#include "pl_log_source.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

namespace policy_loop {

namespace {

const size_t kChunk = 65536;

double NowMs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) * 1000.0 + static_cast<double>(ts.tv_nsec) / 1e6;
}

// True once the budget's wall-clock half is spent. `deadline` is in the same
// monotonic milliseconds as NowMs.
bool DeadlinePassed(double deadline)
{
    return deadline > 0 && NowMs() >= deadline;
}

// Milliseconds left until `deadline`, or -1 (block indefinitely) when there is
// no deadline.
int RemainingMs(double deadline)
{
    if (deadline <= 0) {
        return -1;
    }
    double left = deadline - NowMs();
    if (left <= 0) {
        return 0;
    }
    return static_cast<int>(left) + 1;
}

bool BudgetExhausted(const std::string &out, const ReadBudget &budget)
{
    return budget.maxBytes > 0 && static_cast<long long>(out.size()) >= budget.maxBytes;
}

double DeadlineFor(const ReadBudget &budget)
{
    return budget.maxMs > 0 ? NowMs() + static_cast<double>(budget.maxMs) : 0.0;
}

std::string Errno(const char *what)
{
    return std::string(what) + ": " + std::strerror(errno);
}

// --------------------------------------------------------------------------
// Blocking reads: a file, or stdin
// --------------------------------------------------------------------------

/*
 * Reads `fd` to EOF. Every read here returns what is available and then blocks
 * for more, which is what a file and a pipe both do, so no polling is needed.
 */
bool ReadToEof(int fd, std::string *out, std::string *err)
{
    char buf[kChunk];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            *err = Errno("read");
            return false;
        }
        if (n == 0) {
            return true;
        }
        out->append(buf, static_cast<size_t>(n));
    }
}

// --------------------------------------------------------------------------
// Polled reads: a stream that may never produce EOF
// --------------------------------------------------------------------------

/*
 * Reads `fd` until EOF, the deadline, or the byte budget. Used for the two
 * sources that can run forever.
 *
 * `block` is what separates a pipe from /dev/kmsg. A pipe gives EOF when the
 * writer exits, so waiting indefinitely for the first byte is correct. /dev/kmsg
 * never signals EOF and never returns 0, so waiting on it is not: it must be
 * read until the budget ends the read, and its fd is opened non-blocking so a
 * quiet kernel cannot park the process.
 *
 * A read that returns 0 for a non-blocking descriptor is not EOF -- it means
 * nothing was buffered -- so it is retried until the deadline rather than
 * treated as the end of the stream.
 */
bool ReadPolled(int fd, std::string *out, std::string *err, const ReadBudget &budget, bool block)
{
    double deadline = DeadlineFor(budget);
    char buf[kChunk];
    for (;;) {
        if (BudgetExhausted(*out, budget) || DeadlinePassed(deadline)) {
            return true;
        }
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int rc = poll(&pfd, 1, RemainingMs(deadline));
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            *err = Errno("poll");
            return false;
        }
        if (rc == 0) {
            return true;                    // deadline reached
        }
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!block && DeadlinePassed(deadline)) {
                    return true;
                }
                continue;
            }
            *err = Errno("read");
            return false;
        }
        if (n == 0) {
            // EOF on a pipe; on a non-blocking character device this is an
            // empty drain, so keep waiting unless there is nothing to wait for.
            if (block || DeadlinePassed(deadline)) {
                return true;
            }
            continue;
        }
        out->append(buf, static_cast<size_t>(n));
    }
}

// --------------------------------------------------------------------------
// Sources
// --------------------------------------------------------------------------

class FileSource : public LogSource {
public:
    explicit FileSource(const std::string &path) : path_(path) {}

    bool ReadAll(std::string *out, std::string *err, const ReadBudget &budget) override
    {
        (void)budget;                       // a file is finite; no budget needed
        if (path_.empty() || path_ == "-") {
            return ReadToEof(STDIN_FILENO, out, err);
        }
        int fd = open(path_.c_str(), O_RDONLY);
        if (fd < 0) {
            *err = path_ + ": " + std::strerror(errno);
            return false;
        }
        bool ok = ReadToEof(fd, out, err);
        close(fd);
        return ok;
    }

    std::string Tag() const override { return "file"; }
    std::string Describe() const override
    {
        return (path_.empty() || path_ == "-") ? "stdin" : path_;
    }
    bool IsSampled() const override { return false; }

private:
    std::string path_;
};

class StdinSource : public LogSource {
public:
    bool ReadAll(std::string *out, std::string *err, const ReadBudget &budget) override
    {
        (void)budget;
        return ReadToEof(STDIN_FILENO, out, err);
    }

    std::string Tag() const override { return "stdin"; }
    std::string Describe() const override { return "stdin"; }
    bool IsSampled() const override { return false; }
};

/*
 * Stops `pid` and reaps it.
 *
 * SIGTERM first, because a log producer is expected to die on it, then SIGKILL
 * if it will not. The loop is bounded: this runs on the path that exists to
 * *avoid* blocking, so it may not block either.
 */
void Terminate(pid_t pid, int *status)
{
    kill(pid, SIGTERM);
    for (int i = 0; i < 50; ++i) {          // up to 500 ms
        if (waitpid(pid, status, WNOHANG) == pid) {
            return;
        }
        usleep(10000);
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
}

class CommandSource : public LogSource {
public:
    explicit CommandSource(const std::string &cmd) : cmd_(cmd) {}

    bool ReadAll(std::string *out, std::string *err, const ReadBudget &budget) override
    {
        int fds[2];
        if (pipe(fds) != 0) {
            *err = Errno("pipe");
            return false;
        }
        pid_t pid = fork();
        if (pid < 0) {
            close(fds[0]);
            close(fds[1]);
            *err = Errno("fork");
            return false;
        }
        if (pid == 0) {
            // Child. /bin/sh rather than a direct exec: the useful commands here
            // are written with arguments and pipes ("hilog -x -t kmsg"), and
            // re-implementing word splitting would be its own source of bugs.
            close(fds[0]);
            if (dup2(fds[1], STDOUT_FILENO) < 0) {
                _exit(127);
            }
            close(fds[1]);
            execl("/bin/sh", "sh", "-c", cmd_.c_str(), static_cast<char *>(nullptr));
            _exit(127);
        }

        close(fds[1]);
        bool ok = ReadPolled(fds[0], out, err, budget, /* block= */ true);
        close(fds[0]);
        if (!ok) {
            int ignored = 0;
            Terminate(pid, &ignored);
            return false;
        }

        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == 0) {
            // Still running, so the budget ended the read rather than the
            // command -- which is the normal case for a tailing producer.
            // Waiting here would re-impose exactly the delay the budget just
            // removed, so the producer is stopped instead.
            Terminate(pid, &status);
            return true;
        }
        // It exited on its own, so its status is meaningful: a command that
        // failed outright produced no output, and presenting that as an empty
        // log would be a silent lie.
        if (!WIFEXITED(status)) {
            *err = "command killed by signal " + std::to_string(WTERMSIG(status)) + ": " + cmd_;
            return false;
        }
        if (WEXITSTATUS(status) != 0) {
            *err = "command exited with status " + std::to_string(WEXITSTATUS(status)) + ": " + cmd_;
            return false;
        }
        return true;
    }

    std::string Tag() const override { return "cmd"; }
    std::string Describe() const override { return "cmd:" + cmd_; }
    bool IsSampled() const override { return true; }

private:
    std::string cmd_;
};

class KmsgSource : public LogSource {
public:
    bool ReadAll(std::string *out, std::string *err, const ReadBudget &budget) override
    {
        int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            *err = std::string("/dev/kmsg: ") + std::strerror(errno);
            return false;
        }
        bool ok = ReadPolled(fd, out, err, budget, /* block= */ false);
        close(fd);
        return ok;
    }

    std::string Tag() const override { return "kmsg"; }
    std::string Describe() const override { return "/dev/kmsg"; }
    bool IsSampled() const override { return true; }
};

} // namespace

std::unique_ptr<LogSource> MakeFileSource(const std::string &path)
{
    return std::unique_ptr<LogSource>(new FileSource(path));
}

std::unique_ptr<LogSource> MakeStdinSource()
{
    return std::unique_ptr<LogSource>(new StdinSource());
}

std::unique_ptr<LogSource> MakeCommandSource(const std::string &cmd)
{
    return std::unique_ptr<LogSource>(new CommandSource(cmd));
}

std::unique_ptr<LogSource> MakeKmsgSource()
{
    return std::unique_ptr<LogSource>(new KmsgSource());
}

} // namespace policy_loop
