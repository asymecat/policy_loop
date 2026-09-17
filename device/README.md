# denial_check —— PolicyLoop 的设备端组件

宿主侧（`~/policy_loop` 的 Python 引擎）回答"这条 denial 该不该放行、最小修复是什么"；
这个目录是把它**做成 OpenHarmony 系统组件**的那一半：一个跑在设备上的 C++ 二进制，
不依赖宿主机、不依赖网络、不依赖 LLM。

它存在的理由是可验证的那条：**审计设备自己的策略，应该是平台能力，而不是一件必须先有
PC 和串口线才能做的事**。

```
device/
  selinux_adapter/          ← 按 OpenHarmony 源码路径镜像
    framework/policycoreutils/src/pl_*.cpp     核心库（6 个 TU）
    framework/tools/denial_check/test.cpp      命令行外壳与固定 API
    interfaces/policycoreutils/include/pl_*.h  接口
  patches/
    selinux_adapter-BUILD.gn.patch             对上游 BUILD.gn 的加法
  install.sh                                    铺回 OH 源码树
```

镜像而非源码：这个组件由 OpenHarmony 自己的 GN 构建在**完整源码树**里编译，
`install.sh` 负责把它放回构建期望的位置。改动请改这里再 `install.sh`，
或改 OH 树后同步回来——两边不可长期分叉。

## 依赖规则（这是可检查的，不是声明）

核心是 `libdenial_check_core` 这个**独立静态库**，不是 `libservice_checker` 之类会随系统
发行的库的一部分。原因：它**不得**引入 hilog 或 libselinux——它的全部意义就是在任何
能读到输入的域下运行，并把结论写 stdout 而不是写 hilog。

独立成目标让这条规则变成可检查的：该 target 的 `external_deps` 为空，
所以它能链到的东西只有 libc/libc++/libm。`tools/devbuild.sh check` 另外扫一遍
被禁的头文件（`std::filesystem` / `std::regex` / 异常）——它们在宿主上编得过，
在设备镜像上要么不可用、要么体积不可接受。

## 装进 OH 树并构建

```bash
./device/install.sh                  # 默认 $HOME/ohos_src
./device/install.sh /path/to/ohos    # 或显式指定

# 交叉编译（DAYU200 是 32 位 arm 用户态，target_cpu 必须是 "arm"）
~/ohos_src/build.sh --product-name rk3568 --build-target denial_check
```

产出的 `denial_check` 已设 `install_enable = true`，随镜像进 `/system/bin/denial_check`，
PATH 直呼。

**宿主快速回路**（不碰 OH 工具链，用来跑掉 ~90% 的验证）：

```bash
./tools/devbuild.sh          # 带 ASan/UBSan → /tmp/denial_check_host
./tools/devbuild.sh release  # -O2
./tools/devbuild.sh check    # 设备等价 cflags + 禁用头文件扫描
```

## 固定 API

设备端只暴露几个固定入口，语义在内、编排在外——这样 agent 的能力边界是可控的。

| 入口 | 作用 |
|---|---|
| `--selftest` | 21 组固定向量，不需要索引和日志。用来把"跑不起来"和"算错了"分开 |
| `--index-info` | 加载索引后打印计数。用来确认索引完整送达——计数必须等于 exporter 的摘要 |
| `--query <file>` | 一行一条策略查询，JSONL 出裁决（宿主/设备查询差分用） |
| `--dump-denials` | 只解析，逐条 JSON。两侧同形，所以比较就是 `diff` |
| `--converge` | 聚类日志并出收敛报告，字段与宿主引擎逐个相同，可直接 diff |
| `--explain <line>` | 解释**一条** `avc: denied`：根因、策略怎么说、有无最小修复 |
| `--case <file>` | 逐条记录的固定 per-record API：调用方自己切日志再送进来，而不是向设备要一份成品报告 |

`--explain` 与 `--case` 都**只输出建议，绝不写盘**。

## 验证

宿主侧的 `tests/diff_device.py` 是差分门禁；`tests/` 下的 `test_case_api.py` /
`test_export.py` 等测的是差分测不到的形状契约。真机上的做法与实测值见
`docs/eval-L4.md`。

## 已知债（当前版本的硬伤）

**索引版本不一致。** 宿主 `policy_loop/export/pli.py` 已经写 `@rev 2` 与 `@hap` 段
（承载 `sehap_contexts` 的 APL 映射），而本目录的读取器仍是 `kPliVersion = 1`，
不解析 `@hap`。后果是设备读不了当前导出的索引：

```
denial_check: unsupported PLI revision: @rev 2     # exit 3
```

三个连带影响：① 宿主 `tests/test_case_api.py` 那 4 项在**建了宿主二进制**的机器上会红
（没建的机器自动 skip）；② 差分门禁只能对着手工造的 v1 索引跑，跑不了
`build/pli/ohos-rk3568.pli`；③ 跨层的 C++ 半边没做，`--cross-layer` 目前只有宿主侧。

要做的：`kPliVersion` 提到 2、解析 `@hap` 段、`--index-info` 的
`hap_entries` / `hap_domains` / `hap_names` / `hap_apls` / `hap_debuggable` / `hap_skipped`
计数对齐 exporter。
