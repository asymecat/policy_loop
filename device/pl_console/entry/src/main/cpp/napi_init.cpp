/**
 * PolicyLoop 板端控制台的原生桥。
 *
 * 存在的唯一理由：ArkTS 里没有能启动进程、也没有能跑 C++ 分析引擎的 API。
 * `@ohos.process` 只有 kill/exit/uptime 这类查询，`childProcessManager` 只能拉起
 * 应用自己的 .so，都够不到板上的引擎。
 *
 * 这里**不是**去 exec `/system/bin/denial_check`，而是把引擎源码直接编进来。
 * 三条理由，每条都是实测出来的：
 *
 *   1. exec 路线能走通但会被 SELinux 按在应用域里 —— `allow hap_domain
 *      system_bin_file (file (... execute_no_trans))` 是 `execute_no_trans`，
 *      子进程不换域，所以它能做的事和宿主应用一样多，绕不过任何限制。
 *   2. /system/bin 那份 denial_check 是 9/16 的旧件（137,608 B），只认
 *      `@rev 1`，读不了当前导出器写的索引，而 /system 是只读的换不掉。
 *   3. 应用自己沙箱里的二进制**跑不了**：
 *        (allow normal_hap_attr data_app_el1_file (file (execute)))
 *        neverallow normal_hap_attr normal_hap_data_file_attr:file execute_no_trans;
 *      有 `execute` 却没有 `execute_no_trans`，内核找不到 type_transition 就落回
 *      同域执行，而同域执行恰好被 neverallow 挡死。
 *
 * 编进来之后，索引和日志都以字符串进出，不落盘、不碰系统分区、不依赖任何
 * 板上已有的二进制。应用沙箱读写是自己的权限，绝对够用。
 *
 * 引擎本身是纯标准库的（pl_log_source.cpp 依赖 hilog，那是读 /dev/kmsg 的采集
 * 路径，应用拿不到也不需要，故不打进来）。
 */

#include <napi/native_api.h>

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "pl_avc_parser.h"
#include "pl_converge.h"
#include "pl_index.h"

namespace {

using policy_loop::DenialRecord;
using policy_loop::ExplainResult;
using policy_loop::PlIndex;

// 加载好的索引只留一份：它有两万条规则、解析要 200ms 以上，而每次分析都要用。
std::mutex g_mutex;
std::unique_ptr<PlIndex> g_index;

/*
 * 与 PC 侧 tools/board_bridge.py 的 TOOL_DOMAINS 必须保持一致。
 *
 * 这些域里的 denial 是我们自己的工具（截屏、hdc 落的 root shell、UI 驱动）造成
 * 的，是真实的 denial，但不是板子的缺陷。演示时这两类必须分开讲，所以控制台
 * 给它们打上不同的来源标记。
 */
const std::set<std::string> kToolDomains = {
    "snapshot_display", "su", "uitest", "shell", "sh",
    "dmesg", "toybox", "hdcd", "hdcd_shell",
    // PolicyLoop 自己的采集器同理，而且更近一层：探针的 --debug-log、启动时
    // 摸的 /proc 与 /dev/console，都是我们这个组件的足迹，不是被测固件的缺陷。
    // 漏了它，探针那条会在窗口里冒充「板子自带」。
    "pl_collector",
};

std::string json_string(const std::string &s) {
    return policy_loop::JsonString(s);
}

std::string join(const std::vector<std::string> &parts, const char *sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i > 0) {
            out += sep;
        }
        out += parts[i];
    }
    return out;
}

/*
 * 去重键取的是**这次访问**（源、目标、类、权限集、ioctl 命令），不是日志原文。
 * 内核每次重试都会换一个 pid 和时间戳重新记一遍，`render_service -> dev_mali`
 * 触发 3 次还是 300 次，都是一条判定。
 */
std::string access_key(const DenialRecord &r) {
    std::vector<std::string> perms = r.permissions;
    std::sort(perms.begin(), perms.end());
    std::string key;
    // \x01 作缺席标记：OptStr 区分"缺席"和"空串"，两者是不同的 denial。
    key += r.source_domain.present ? r.source_domain.value : std::string("\x01");
    key += '\x02';
    key += r.target_type.present ? r.target_type.value : std::string("\x01");
    key += '\x02';
    key += r.tclass.present ? r.tclass.value : std::string("\x01");
    key += '\x02';
    key += join(perms, ",");
    key += '\x02';
    key += r.ioctlCmd.present ? r.ioctlCmd.value : std::string("\x01");
    return key;
}

std::string load_index_locked(const std::string &text) {
    std::string err;
    std::unique_ptr<PlIndex> idx = PlIndex::LoadFromText(text, &err);
    if (idx == nullptr) {
        return "{\"ok\": false, \"error\": " + json_string(err) +
               ", \"rev\": \"\", \"rules\": 0, \"source\": \"\"}";
    }
    const std::string rev = idx->rev();
    const long long rules = idx->meta().rules;
    const std::string source = idx->meta().source;
    g_index = std::move(idx);
    return "{\"ok\": true, \"error\": \"\", \"rev\": " + json_string(rev) +
           ", \"rules\": " + std::to_string(rules) +
           ", \"source\": " + json_string(source) + "}";
}

std::string analyze_locked(const std::string &log, int limit) {
    if (g_index == nullptr) {
        return "{\"ok\": false, \"error\": \"索引尚未加载\", \"total\": 0,"
               " \"unique\": 0, \"findings\": []}";
    }

    std::vector<DenialRecord> records = policy_loop::ParseDenials(log);

    struct Slot {
        DenialRecord rec;
        int count = 0;
        bool tool = false;
    };
    std::map<std::string, Slot> seen;
    for (const DenialRecord &r : records) {
        const std::string key = access_key(r);
        auto it = seen.find(key);
        if (it == seen.end()) {
            Slot slot;
            slot.rec = r;
            const std::string dom = r.source_domain.present ? r.source_domain.value : "";
            slot.tool = kToolDomains.count(dom) != 0;
            it = seen.emplace(key, std::move(slot)).first;
        }
        it->second.count++;
    }

    std::vector<Slot *> ordered;
    ordered.reserve(seen.size());
    for (auto &kv : seen) {
        ordered.push_back(&kv.second);
    }
    // 板子自带的排前面 —— 那才是演示要讲的东西。
    std::sort(ordered.begin(), ordered.end(), [](const Slot *a, const Slot *b) {
        if (a->tool != b->tool) {
            return !a->tool;
        }
        return a->count > b->count;
    });

    std::map<std::string, int> by_class;
    std::map<std::string, int> by_origin;
    std::string findings = "[";
    int emitted = 0;
    for (const Slot *slot : ordered) {
        ExplainResult res = policy_loop::ExplainDenial(slot->rec.raw, g_index.get());
        if (!res.parsed) {
            continue;  // 这一行不是 denial，跳过而不是报错
        }
        by_class[res.classification]++;
        by_origin[slot->tool ? "tool" : "board"]++;

        if (emitted >= limit) {
            continue;  // 统计走全量，列表只列前 limit 条
        }
        std::string op;
        if (!res.ioctlCmd.empty()) {
            op = "ioctl " + res.ioctlCmd;
        } else {
            op = join(res.requested, " ");
        }
        op += "   ×" + std::to_string(slot->count);

        std::string verdict;
        if (res.needsHuman) {
            verdict = "需人工介入";
        } else {
            verdict = (res.reviewStatus.empty() ? "?" : res.reviewStatus) + " · " +
                      (res.verifyStatus.empty() ? "?" : res.verifyStatus);
        }

        if (emitted > 0) {
            findings += ", ";
        }
        findings += "{\"origin\": " + json_string(slot->tool ? "tool" : "board") +
                    ", \"src\": " + json_string(res.src) +
                    ", \"tgt\": " + json_string(res.tgt + ":" + res.cls) +
                    ", \"op\": " + json_string(op) +
                    ", \"cls\": " + json_string(res.classification) +
                    ", \"fix\": " + json_string(res.patch) +
                    ", \"verdict\": " + json_string(verdict) + "}";
        emitted++;
    }
    findings += "]";

    std::string classes = "{";
    bool first = true;
    for (const auto &kv : by_class) {
        if (!first) {
            classes += ", ";
        }
        classes += json_string(kv.first) + ": " + std::to_string(kv.second);
        first = false;
    }
    classes += "}";

    return "{\"ok\": true, \"error\": \"\", \"total\": " +
           std::to_string(records.size()) +
           ", \"unique\": " + std::to_string(seen.size()) +
           ", \"board\": " + std::to_string(by_origin["board"]) +
           ", \"tool\": " + std::to_string(by_origin["tool"]) +
           ", \"by_classification\": " + classes +
           ", \"findings\": " + findings + "}";
}

// --------------------------------------------------------------------------
// NAPI 胶水
// --------------------------------------------------------------------------

enum class Op { kLoadIndex, kAnalyze };

struct Work {
    Op op = Op::kAnalyze;
    std::string text;      // 索引正文，或日志正文
    int limit = 20;
    std::string out;
    napi_deferred deferred = nullptr;
    napi_async_work work = nullptr;
};

void Execute(napi_env /*env*/, void *data) {
    auto *w = static_cast<Work *>(data);
    std::lock_guard<std::mutex> guard(g_mutex);
    if (w->op == Op::kLoadIndex) {
        w->out = load_index_locked(w->text);
    } else {
        w->out = analyze_locked(w->text, w->limit);
    }
}

void Complete(napi_env env, napi_status /*status*/, void *data) {
    auto *w = static_cast<Work *>(data);
    if (w->deferred != nullptr) {
        napi_value value = nullptr;
        napi_create_string_utf8(env, w->out.c_str(), w->out.size(), &value);
        napi_resolve_deferred(env, w->deferred, value);
    }
    napi_delete_async_work(env, w->work);
    delete w;
}

std::string get_string(napi_env env, napi_value v) {
    size_t len = 0;
    if (napi_get_value_string_utf8(env, v, nullptr, 0, &len) != napi_ok) {
        return std::string();
    }
    std::string s(len, '\0');
    size_t written = 0;
    if (napi_get_value_string_utf8(env, v, &s[0], len + 1, &written) != napi_ok) {
        return std::string();
    }
    s.resize(written);
    return s;
}

napi_value submit(napi_env env, Op op, const std::string &text, int limit) {
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_create_promise(env, &deferred, &promise);

    auto *w = new Work();
    w->op = op;
    w->text = text;
    w->limit = limit;
    w->deferred = deferred;

    napi_value name = nullptr;
    napi_create_string_utf8(env, "plnative.work", NAPI_AUTO_LENGTH, &name);
    napi_create_async_work(env, nullptr, name, Execute, Complete, w, &w->work);
    napi_queue_async_work(env, w->work);
    return promise;
}

/**
 * loadIndex(text: string): Promise<string>
 *
 * 解析一份 PLI 索引并留在原生侧。返回 `{ok, error, rev, rules, source}` 的 JSON。
 * 索引有两万条规则、解析要 200ms 以上，所以放异步，别卡住 UI 线程。
 */
napi_value LoadIndex(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    return submit(env, Op::kLoadIndex, argc >= 1 ? get_string(env, argv[0]) : "", 0);
}

/**
 * analyze(log: string, limit?: number): Promise<string>
 *
 * 对一段 AVC 日志做去重、分类与最小修复，返回与 PC 侧 /state 同形的 JSON
 * （`{ok, error, total, unique, board, tool, by_classification, findings[]}`），
 * 所以 ArkTS 侧的 Finding 接口一行都不用改。
 */
napi_value Analyze(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2] = {nullptr, nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    int limit = 20;
    if (argc >= 2) {
        int32_t v = 0;
        if (napi_get_value_int32(env, argv[1], &v) == napi_ok && v > 0) {
            limit = v;
        }
    }
    return submit(env, Op::kAnalyze, argc >= 1 ? get_string(env, argv[0]) : "", limit);
}

napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"loadIndex", nullptr, LoadIndex, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"analyze", nullptr, Analyze, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "plnative",
    .nm_priv = nullptr,
    .reserved = {0},
};

}  // namespace

extern "C" __attribute__((constructor)) void RegisterPlNativeModule(void) {
    napi_module_register(&g_module);
}
