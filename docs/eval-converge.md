# 批量收敛工作流（converge）

> 把「permissive 模式下攒下的整份 `avc: denied` 日志」收敛成一份可执行清单：
> 去重 → 逐案判定 → 可自动最小修复 / 需人工决策 / 噪声，附 enforcing 就绪度。
> 确定性内核，纯标准库，**只产出建议、绝不自动写 .te**。

## 用法

```bash
python -m policy_loop.converge \
  --log    <denial 日志文件> \
  --policy <sepolicy 目录或 .te> \
  --json   data/reports/converge.json \   # 可选
  --md     converge.md                    # 可选：人读报告
```

不带 `--policy` 时只能做去重统计（`unclassified_no_policy`），不做策略判定。

## 流水线

1. **聚类去重**：`denial.fingerprint` 按逻辑访问 `(src,tgt,class,perms,ioctl)` 做键
   （`perms` 排序无关），pid/comm/path 等噪音不参与 → 几千条塌缩成唯一案例。
2. **快路判定**：每唯一案例先做廉价策略查询（`has_access`/`neverallow`/`ioctl`）：
   - 撞 neverallow → 直接转人工（拒绝自动放权）；
   - 已允许 + `permissive=1` → 噪声；
   - 已允许 + enforcing → 域/标签问题转人工；
   - 其余才进入完整 6-Agent 闭环（Log→Policy→Security→Repair→Review→Verify）。
   这一层把「逐条跑闭环」的成本降到只在真缺口上花。
3. **守门**：闭环判 AUTO 的补丁必须能作为最小修复落点验证，否则降级人工
   （见下）。通过后归入 `auto_repairable`。
4. **产出**：去重比 / 各根因分布 / 去重后最小补丁集合（含覆盖案例与条数）/
   需人工清单（附原因与样例 raw）/ enforcing 就绪度一段话。

## 补丁守门（为什么自动项可信）

闭环自身的 Review/Verify 只做「应用后能消除 denial、无回归」的名字级匹配，
无法发现「规则本身引用的是不存在的类型/类」。converge 据此补了五道守门，
命中的一律从 AUTO 降级为 needs_human：

| # | 情形 | 示例 | 处置 |
|---|---|---|---|
| 1 | 目标被解析成 MLS 级别 | `tcontext=u:charger_exec:s0`（丢 `object_r`）→ tgt=`s0` | 人工复核上下文 |
| 2 | 目标是 `default_*` 占位符 | `allow X default_service:samgr_class get`（真实修复落到 `sa_*`/`hdf_device_manager`） | 交 M3 service 映射 |
| 3 | 主体/目标不在策略语料 | `src=file`、`tgt=sa_1401_service`（设备新增域 / 数字 service 标签） | 补丁无法落点验证 |
| 4 | 对象类不存在 | 手写日志笔误 `samar_class`/`samger_class`/`dit` | 补丁无法编译 |
| 5 | 空权限补丁 | ioctl-only 缺口经 allowxperm 语义后得 `allow A B:c { };` | 转人工给 allowxperm |

> 这些大多来自**上游 .te 里手维护的 denial 注释**（会缺 `object_r`、拼错类名、
> 引用 CIL 生成/数字 service 类型），而非真实内核日志。真机 permissive dump 干净得多，
> 守门主要是挡住"照抄可疑注释"这类误修复。

## 实测（2026-09，真实上游语料，规则索引 21790）

| 批 | 输入 | 唯一 | 可自动修复 | 需人工 | 噪声/已允许 | 说明 |
|---|---|---|---|---|---|---|
| A 真实缺口 | 144 条 replay-uncovered | 134 | 38 | 96 | 0 | 真缺失案例；38 个最小补丁全部通过守门 |
| B golden 全量 | 5161 条 | 4911 | 40 | 3319 | 1552 | 覆盖/已修复不误报成自动补丁 |
| C permissive-only | 3557 条 | 3402 | 34 | 1807 | 1561 | 最贴近「permissive 设备 dump」的输入形态 |

- 去重比：B ≈ 1.05（上游日志本身每访问一次），A/C 相似；对真实重复刷屏的设备日志
  去重效果会更显著。
- **不误报**：B/C 中已允许（含后来才修复）的 denial **零**落进 `auto_repairable`；
  covered+permissive=1 → 噪声，covered+enforcing → `DOMAIN_OR_LABEL_MISMATCH` 转人工。
- **拒绝越权**：B 的 2645 / C 的 1771 个唯一案例命中 neverallow → 一律不自动放权，
  转人工（多为 HAP 域越权访问，需架构/标签决策，不是加 allow 能解决的）。
- **守门降级**：约四成"看似可修"的案例因主体/目标/类不在语料而被降级人工 ——
  这是**保守而非漏修**：converge 只对能在当前语料证明落点的补丁打"可自动"。

## 边界与已知局限

- **ioctl-only 缺口**：当唯一缺失权限是 `ioctl` 且策略既无 `allow ioctl` 也无
  allowxperm 白名单可指时，修复路径可能给出空权限补丁 → 守门 5 兜住转人工。
  真正的 allowxperm 最小补丁生成是后续工作（Review/Verify 语义本轮不动）。
- **service 二次映射**：`default_service`/数字 `sa_<id>_service` 目标需 `service=`
  字段映射到具体已声明类型（M3）。
- **快路 vs 闭环等价性**：快路判定与 `SecurityAgent.classify` 对 `(neverallow,
  ioctl, all_allowed, permissive)` 的决策一致；两种情况下已允许类 denial 不会进
  Repair/Review 的补丁路径。
- 报告口径诚实：`exact_min` 类自洽指标不对外夸大为独立金标准；收敛就绪度只服务
  "permissive → enforcing" 的决策，真机回归在 L4。

## 复现

```bash
# 生成两条验证批（来自提交的 golden 与 replay 落盘）
python3 -c "…from replay-report uncover…"      # 见 git 提交历史 / CI 说明
python -m policy_loop.converge --log <批> --policy data/raw/oh-selinux/sepolicy \
  --json data/reports/converge-<批>.json
python -m unittest tests.test_converge -v        # 18 项
```

> 语料 `data/raw/oh-selinux` 不入库；无语料时 converge 走 no-index 去重路径。
