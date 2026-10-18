"""DocGate 得**有牙** —— 每一条判据都配一个「改坏了它得红」的反控。

为什么值得单独写一整套测试
--------------------------
这道门就是为了防一次真实事故：`docs/figs/` 的配图在撒谎（fig2 画着一条代码里
不存在的 Verify→Repair 回路、三张图把 7 个 Agent 写成 6 个），**没有任何东西
因此变红**，靠人肉看图，5 天后才发现。

所以这里测的**不是**「门禁在干净树上绿」（那条 `tools/docgate.py` 自己就跑），
而是「在**坏**树上红，而且红得准」：

* 红在正确的位置（`file:line` + 期望/实得），不是一句"好像有问题"；
* 红成正确的种类（值不符 vs 锚点没了，是两回事）；
* **绝不在证明不了的时候装通过** —— 锚点消失、探针数出 0、板端源码不在，
  一律 FAIL 或出声 SKIP，绝不当 OK。记成静默跳过就等于重演事故。

全部在 tmp 树上跑（自带一份迷你 facts.json），所以本仓文稿正在被改写的那些天里，
这些测试照样说明问题。两个口径都要跑：``python -m pytest -q`` 与
``python -m unittest discover -s tests``。
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------- #
# 迷你"仓库"：一份能全绿的最小的事实集合
# --------------------------------------------------------------------------- #

REPORT_MD = """\
# 迷你报告

本机实测索引规模：1,234 条规则；六步主链上的 3 Agent（含只读的一个）。

收敛路径上有 2 道守门。

![迷你架构图](figs/fig1.png)

占位符：【待填】
"""

FIG_PY = '''\
"""迷你图脚本 —— 测试替身，一 import 就会画图，所以门禁只准 AST 读它。"""

CAPTION = "迷你架构：1,234 条规则"
BAND = "3 Agent 流水线"
'''

CONVERGE_PY = '''\
"""迷你收敛实现（只有 apply_guards 会被读）。"""


def apply_guards(case):
    """这道 docstring 不该被算成一道守门。"""
    if case == "a":
        return "甲类可疑"
    if case == "b":
        return "乙类可疑"
    return None
'''

ORCH_PY = '''\
"""迷你编排器。"""

_PIPELINE = ("Log", "Policy", "Repair")
'''

CPP = """\
void ApplyGuards(Verdict* verdict) {
    std::string why;
    if (caseA) { why = "甲类可疑"; }
    else if (caseB) { why = "乙类可疑"; }
    verdict->why = why;
}
"""

CPP_REL = "device/selinux_adapter/pl_converge.cpp"

README_MD = "# 迷你仓\n\n索引 1,234 条规则。\n"

G_RULES = r"([0-9,]+)\s*条规则"
G_AGENTS = r"([一二三四五六七八九十0-9]+)\s*Agent"
G_GUARDS = r"([一二三四五六七八九十0-9]+)\s*道守门"


def manifest() -> dict:
    """每次现造一份 —— 测试之间不许共享可变状态。"""
    return {
        "schema": 1,
        "updated": "2026-10-15",
        "facts": {
            "index.rules": {"value": 1234, "norm": "int_thousands",
                            "probe": None, "scope": "当前"},
            "guards.apply_guards_branches": {"value": 2, "norm": "cn_or_int",
                                             "probe": "guards.py_branches",
                                             "scope": "当前"},
            "pipeline.agents": {"value": 3, "norm": "cn_or_int",
                                "probe": "pipeline.agents", "scope": "当前"},
        },
        "sites": [
            {"fact": "index.rules", "file": "docs/report.md",
             "context": "实测索引规模", "pattern": G_RULES},
            {"fact": "pipeline.agents", "file": "docs/report.md",
             "context": "六步主链上的", "pattern": G_AGENTS},
            {"fact": "guards.apply_guards_branches", "file": "docs/report.md",
             "context": "收敛路径上有", "pattern": G_GUARDS},

            {"fact": "index.rules", "file": "docs/figs/make_figs.py",
             "context": "迷你架构", "pattern": G_RULES},
            {"fact": "pipeline.agents", "file": "docs/figs/make_figs.py",
             "context": "Agent 流水线", "pattern": G_AGENTS},
        ],
        "wait_for": {
            "why": "反向扫描：出现这些句式的地方必须已被某个 site 覆盖",
            "grammars": [
                {"file": "docs/figs/make_figs.py", "pattern": G_RULES,
                 "severity": "fail"},
                {"file": "docs/figs/make_figs.py", "pattern": G_AGENTS,
                 "severity": "fail"},
                {"file": "docs/report.md", "pattern": G_RULES,
                 "severity": "warn"},
            ],
        },
        "mirrors": [
            {
                "id": "guards.py_vs_cpp",
                "py": {"file": "policy_loop/converge.py", "func": "apply_guards"},
                "cpp": {"file": CPP_REL, "func": "ApplyGuards"},
                "signatures": ["甲类可疑", "乙类可疑"],
            },
            {
                "id": "pipeline.agents_vs_fig2",
                "fig": {"file": "docs/figs/make_figs.py",
                        "context": "Agent 流水线", "pattern": G_AGENTS},
                "probe": "pipeline.agents",
            },
        ],
        "placeholders": {
            "why": "只许变少",
            "entries": [{"file": "docs/report.md", "pattern": "【待填】",
                         "count": 1, "expires": "2026-11-01"}],
        },
        "docx": {
            "md": "docs/report.md",
            "builder": "tools/build_report_docx.py",
            "artifact": "docs/report.docx",
            "provenance_env": {"pandoc": "3.1.11", "python_docx": "1.2.0"},
        },
        "figures": {
            "script": "docs/figs/make_figs.py",
            "outputs": ["docs/figs/fig1.png"],
            "consumers": ["docs/report.md"],
        },
        "managed": ["docs/figs/make_figs.py", "docs/report.md", "README.md",
                    "policy_loop/converge.py"],
    }


def build_tree(tmp: Path, git: bool = True, **overrides) -> Path:
    """铺一棵迷你仓。``overrides`` 覆盖清单里的顶层键（如 ``facts=``）。"""
    files = {
        "docs/report.md": REPORT_MD,
        "docs/figs/make_figs.py": FIG_PY,
        "docs/figs/fig1.png": "not-a-real-png",
        "policy_loop/converge.py": CONVERGE_PY,
        "policy_loop/agents/orchestrator.py": ORCH_PY,
        CPP_REL: CPP,
        "README.md": README_MD,
    }
    for rel, text in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    man = manifest()
    man.update(overrides)
    (tmp / "docs" / "facts.json").write_text(
        json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")

    if git:
        _git_init(tmp)
    return tmp


def _git_init(tmp: Path) -> None:
    """让 figures 走「git 谱系」那条判据而不是 SKIP（git 不在就退回非 git 树）。"""
    if shutil.which("git") is None:
        return
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t",
                  "-c", "commit.gpgsign=false", "commit", "-qm", "init"]):
        subprocess.run(["git", "-C", str(tmp), *args], capture_output=True, text=True)


def load_docgate():
    path = ROOT / "tools" / "docgate.py"
    spec = importlib.util.spec_from_file_location("docgate_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod     # dataclass 解析注解时要能从 sys.modules 找到自己
    spec.loader.exec_module(mod)
    return mod


def _results(mod, root: Path, **kw) -> dict:
    ctx = mod.Ctx(root=Path(root),
                  man=mod.load_manifest(Path(root) / "docs" / "facts.json"), **kw)
    return mod.run(ctx)


def _flat(results: dict) -> list:
    return [f for fs in results.values() for f in fs]


def _fails(results: dict) -> list:
    return [f for f in _flat(results) if f.severity == "fail"]


def _warns(results: dict) -> list:
    return [f for f in _flat(results) if f.severity == "warn"]


def _all_of(results: dict, kind: str) -> list:
    return [f for f in _flat(results) if f.kind == kind]


def _find(results: dict, kind: str):
    found = _all_of(results, kind)
    if not found:
        raise AssertionError(
            f"没找到 kind={kind}；实得 {[f.kind for f in _flat(results)]}")
    return found[0]


def _main(mod, root: Path, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = mod.main(["--root", str(root), *args])
    return code, buf.getvalue()


def _snapshot(root: Path) -> dict:
    """工作区快照（跳过 .git 与 __pycache__ —— 它们不是"文稿产物"）。"""
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or ".git" in rel.parts or "__pycache__" in rel.parts:
            continue
        out[str(rel)] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


class DocGateTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.mod = load_docgate()
        self.addCleanup(self._tmp.cleanup)

    # -- 正控：干净树必须绿 ------------------------------------------------ #

    def test_clean_tree_is_green(self):
        build_tree(self.root)
        results = _results(self.mod, self.root)
        self.assertEqual(_fails(results), [], f"不该有失败：{_fails(results)}")
        self.assertEqual(_warns(results), [], f"不该有警告：{_warns(results)}")
        self.assertEqual(_main(self.mod, self.root)[0], 0)

    def test_gate_writes_nothing(self):
        """门禁自己不写盘 —— 否则"改不动代码就去改期望值"会换个形式重演。"""
        build_tree(self.root)
        before = _snapshot(self.root)
        code, _ = _main(self.mod, self.root)
        self.assertEqual(code, 0)
        self.assertEqual(_snapshot(self.root), before)

    def test_json_out_is_the_only_file_written(self):
        build_tree(self.root)
        before = set(_snapshot(self.root))
        out = self.root / "out" / "dg.json"
        code, _ = _main(self.mod, self.root, "--json", str(out))
        self.assertEqual(code, 0)
        self.assertTrue(out.is_file())
        self.assertEqual(set(_snapshot(self.root)) - before, {"out/dg.json"})
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["counts"]["fail"], 0)
        # 迷你树里没有 report.docx ⇒ docx 一项是 SKIP；verdict 如实写 skip 而不是 ok，
        # 因为这道门的口径就是"跳过不算通过"。
        self.assertEqual(payload["verdict"], "skip")
        self.assertEqual(payload["counts"]["skip"], 1)
        self.assertIn("facts", payload["checks"])

    def test_emit_manifest_writes_nothing(self):
        build_tree(self.root)
        before = _snapshot(self.root)
        code, text = _main(self.mod, self.root, "--emit-manifest")
        self.assertEqual(code, 0)
        self.assertIn("sites", json.loads(text.split("\n（以上")[0]))
        self.assertEqual(_snapshot(self.root), before, "刷新通道只写 stdout")

    # -- 反控 1：文稿的数字与清单不符 -------------------------------------- #

    def test_value_mismatch_red_with_location(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD.replace("1,234", "1,999"), encoding="utf-8")
        f = _find(_results(self.mod, self.root), "value-mismatch")
        self.assertEqual((f.check, f.severity), ("facts", "fail"))
        self.assertEqual(f.file, "docs/report.md")
        self.assertEqual(f.line, 3, "应精确指到那一行")
        self.assertEqual((f.expected, f.got), (1234, 1999))
        self.assertEqual(_main(self.mod, self.root)[0], 1)

    def test_reverse_scan_catches_unregistered_claim_in_figure(self):
        """新写一句没人登记的话 —— 正向检查看不见，这一步才抓得到。"""
        build_tree(self.root)
        fig = self.root / "docs" / "figs" / "make_figs.py"
        fig.write_text(FIG_PY + '\nFOOT = "覆盖 9,999 条规则"\n', encoding="utf-8")
        f = _find(_results(self.mod, self.root), "unregistered-claim")
        self.assertEqual(f.severity, "fail", "图脚本上的未登记声明=红（图是给评委看的门面）")
        self.assertEqual(f.file, "docs/figs/make_figs.py")

    def test_reverse_scan_in_prose_is_warn_not_fail(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD + "\n另有一处 8,888 条规则的说明。\n", encoding="utf-8")
        f = _find(_results(self.mod, self.root), "unregistered-claim")
        self.assertEqual(f.severity, "warn", "散文里可能只是措辞撞车，先黄后红")

    def test_exempt_is_honored(self):
        """exempt = 口径豁免：那句话里也有个数字，但说的不是这件事。

        豁免词必须是**不含数字**的稳定片段 —— 拿数字本身当豁免词，改数字就等于
        把豁免一起改没了，那是自欺（真实的 report.md 里也踩过这个形状）。
        """
        build_tree(self.root)
        man = json.loads((self.root / "docs" / "facts.json").read_text(encoding="utf-8"))
        for s in man["sites"]:
            if s["fact"] == "pipeline.agents" and s["file"] == "docs/report.md":
                s["exempt"] = ["只读的一个"]
        (self.root / "docs" / "facts.json").write_text(
            json.dumps(man, ensure_ascii=False), encoding="utf-8")
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD.replace("3 Agent", "9 Agent"), encoding="utf-8")
        results = _results(self.mod, self.root)
        self.assertEqual(_all_of(results, "value-mismatch"), [])
        self.assertTrue([f for f in _flat(results)
                         if f.check == "facts" and f.severity == "ok"],
                        "豁免不等于整条 site 消失，别把豁免做成静音开关")

    # -- 反控 2：「我证明不了这句话了」必须是红，不是跳过 ------------------ #

    def test_missing_anchor_is_fail_not_skip(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD.replace("本机实测索引规模：1,234 条规则",
                                        "本机跑过一遍，规模见附录"), encoding="utf-8")
        f = _find(_results(self.mod, self.root), "missing-site")
        self.assertEqual(f.severity, "fail",
                         "锚点没了 = 这句话再也没被验过 —— 记 SKIP 就是安静失效")
        self.assertIn("--emit-manifest", f.message, "报错要给出下一步怎么做")
        self.assertEqual(_main(self.mod, self.root)[0], 1)

    def test_probe_counting_zero_branches_is_fail(self):
        """探针形状失效（数出 0）也不能装通过。"""
        build_tree(self.root)
        (self.root / "policy_loop" / "converge.py").write_text(
            "def apply_guards(case):\n    return None\n", encoding="utf-8")
        self.assertTrue(_all_of(_results(self.mod, self.root), "probe-broken"))

    def test_dead_anchor_in_mirror_is_fail(self):
        build_tree(self.root)
        fig = self.root / "docs" / "figs" / "make_figs.py"
        fig.write_text(FIG_PY.replace("Agent 流水线", "编排链"), encoding="utf-8")
        hits = [f for f in _all_of(_results(self.mod, self.root), "missing-site")
                if f.check == "mirrors"]
        self.assertTrue(hits, "图与代码那条镜像的锚点也没了，必须各自报一次")

    # -- 反控 3：两份实现 / 图与代码必须说同一句话 ------------------------- #

    def test_branch_count_drift_is_caught(self):
        build_tree(self.root)
        conv = self.root / "policy_loop" / "converge.py"
        conv.write_text(CONVERGE_PY.replace(
            "    return None\n",
            '    if case == "c":\n        return "丙类可疑"\n    return None\n'),
            encoding="utf-8")
        f = _find(_results(self.mod, self.root), "branch-count-drift")
        self.assertEqual(f.severity, "fail")
        self.assertEqual(f.expected, 2, "登记的签名条数")
        self.assertEqual(f.got, (3, 2), "(主机, 板端) —— 只有一侧加了分支")

    def test_signature_drift_is_caught(self):
        """措辞改写：判据是「两侧各**恰好**一次」，所以改词和删分支一样会被抓到。"""
        build_tree(self.root)
        (self.root / CPP_REL).write_text(
            CPP.replace("乙类可疑", "丙类可疑"), encoding="utf-8")
        f = _find(_results(self.mod, self.root), "signature-drift")
        self.assertEqual(f.got, (1, 0), "(主机, 板端) 各出现几次")
        self.assertIn("乙类可疑", f.message, "报文要说清是哪一条签名漂了")

    def test_mirror_cpp_absent_is_skip_with_warning(self):
        """板子那份源码不在 = 跳过，但**必须出声**说「跳过 ≠ 一致」。"""
        build_tree(self.root)
        (self.root / CPP_REL).unlink()
        f = _find(_results(self.mod, self.root), "probe-unavailable")
        self.assertEqual(f.severity, "skip")
        self.assertIn("跳过 ≠ 一致", f.message)

    def test_figure_vs_code_is_caught(self):
        """这次事故的原形：图上画 3 个 Agent，代码里是 4 个。"""
        build_tree(self.root)
        (self.root / "policy_loop" / "agents" / "orchestrator.py").write_text(
            ORCH_PY.replace('("Log", "Policy", "Repair")',
                            '("Log", "Policy", "Repair", "Verify")'),
            encoding="utf-8")
        f = _find(_results(self.mod, self.root), "figure-vs-code")
        self.assertEqual((f.expected, f.got), (4, 3))
        self.assertEqual(f.file, "docs/figs/make_figs.py")

    def test_live_catches_manifest_edited_to_match_the_lie(self):
        """**这条最要紧**：文稿与清单一起改谎，默认检查看不出来，`--live` 才见真章。

        选的是一条**只在散文里出现**的口径（守门数）—— 这样"改谎改全套"之后
        默认检查确实全绿，才谈得上证明 `--live` 补上了那个洞。
        """
        man = manifest()
        man["facts"]["guards.apply_guards_branches"]["value"] = 4
        build_tree(self.root, facts=man["facts"])
        md = self.root / "docs" / "report.md"
        md.write_text(md.read_text(encoding="utf-8").replace("2 道守门", "4 道守门"),
                      encoding="utf-8")

        self.assertEqual(_fails(_results(self.mod, self.root)), [],
                         "光看文稿与清单，谎话是圆的")
        f = _find(_results(self.mod, self.root, live=True), "live-mismatch")
        self.assertEqual((f.expected, f.got), (4, 2))

    def test_manifest_only_edit_does_not_turn_red_into_green(self):
        """反过来的那一半：把清单改成跟文稿一致，`--live` 立刻把差异顶回来。"""
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD.replace("2 道守门", "4 道守门"), encoding="utf-8")
        self.assertEqual(_main(self.mod, self.root)[0], 1)   # 默认就该红
        self.assertIn("value-mismatch", [f.kind for f in _fails(
            _results(self.mod, self.root))])

    def test_fact_without_probe_is_warned_under_live(self):
        build_tree(self.root)
        results = _results(self.mod, self.root, live=True)
        f = _find(results, "no-live-probe")
        self.assertEqual(f.severity, "warn", "口径型事实要出声，别当过验过")

    def test_probe_unavailable_is_skip_not_fail(self):
        """语料不在（CI 上的常态）记 SKIP 并出声，而不是判红、也不是装通过。

        语料型探针看的是全局路径（data/raw 只有一个），所以本机拉了语料就跑不到
        这个分支 —— 那时**跳过并说明**，不假装验过。
        """
        if self.mod.docfacts.CORPUS.is_dir():
            self.skipTest("本机已拉语料，这条分支走不到")
        build_tree(self.root)
        man = json.loads((self.root / "docs" / "facts.json").read_text(encoding="utf-8"))
        man["facts"]["index.rules"]["probe"] = "index.rules"
        (self.root / "docs" / "facts.json").write_text(
            json.dumps(man, ensure_ascii=False), encoding="utf-8")

        f = _find(_results(self.mod, self.root, live=True), "probe-unavailable")
        self.assertEqual(f.severity, "skip")
        code, text = _main(self.mod, self.root, "--live", "--strict-env")
        self.assertEqual(code, 2, "环境不满足 + --strict-env ⇒ exit 2（CI 靠它挡假绿）")
        self.assertIn("跳过不算通过", text)

    # -- 反控 4：占位符只许变少 -------------------------------------------- #

    def test_placeholder_growth_is_red(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD + "\n【待填】\n", encoding="utf-8")
        f = _find(_results(self.mod, self.root), "too-many")
        self.assertEqual(f.severity, "fail")
        self.assertEqual((f.expected, f.got), (1, 2))
        self.assertEqual(f.line, 9, "指到该文件里第一处出现的位置")

    def test_placeholder_growth_is_warn_in_draft(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD + "\n【待填】\n", encoding="utf-8")
        self.assertEqual(_find(_results(self.mod, self.root, draft=True),
                               "too-many").severity, "warn")
        self.assertEqual(_main(self.mod, self.root, "--draft")[0], 0,
                         "组装期不该因为漏填而挡住自己")

    def test_placeholder_overdue_is_red(self):
        build_tree(self.root)
        man = json.loads((self.root / "docs" / "facts.json").read_text(encoding="utf-8"))
        man["placeholders"]["entries"][0]["expires"] = "2020-01-01"
        (self.root / "docs" / "facts.json").write_text(
            json.dumps(man, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(_find(_results(self.mod, self.root), "expired").severity, "fail")

    def test_placeholder_fewer_is_only_warn(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD.replace("【待填】", "某大学"), encoding="utf-8")
        self.assertEqual(_find(_results(self.mod, self.root), "fewer").severity, "warn",
                         "填上了是好事，只提醒同步 baseline")

    # -- 反控 5：改脚本没重出图 -------------------------------------------- #

    def test_stale_figure_when_script_newer(self):
        import os
        build_tree(self.root)
        if not (self.root / ".git").exists():
            self.skipTest("本机没 git，走不了谱系判据")
        script = self.root / "docs" / "figs" / "make_figs.py"
        png = self.root / "docs" / "figs" / "fig1.png"
        script.write_text(FIG_PY + "\nX = 1\n", encoding="utf-8")
        os.utime(png, (0, 0))
        os.utime(script, None)
        self.assertEqual(_find(_results(self.mod, self.root), "stale-figure").severity,
                         "fail")

    def test_missing_figure_output_is_red(self):
        build_tree(self.root)
        (self.root / "docs" / "figs" / "fig1.png").unlink()
        self.assertEqual(_find(_results(self.mod, self.root), "missing-output").severity,
                         "fail")

    def test_no_git_is_skip_not_ok(self):
        build_tree(self.root, git=False)
        self.assertEqual(_find(_results(self.mod, self.root), "no-git").severity, "skip")
        # SKIP 不算通过：--strict-env 时要退 2
        self.assertEqual(_main(self.mod, self.root, "--strict-env")[0], 2)

    # -- 反控 6：docx 派生物 ------------------------------------------------- #

    def _docx_finding(self):
        fs = [x for x in _flat(_results(self.mod, self.root)) if x.check == "docx"]
        self.assertEqual(len(fs), 1)
        return fs[0]

    def test_docx_builder_exit_codes_are_mapped(self):
        got_docx = self.mod._python_docx_version()
        if shutil.which("pandoc") is None or got_docx is None:
            self.skipTest("本机缺 pandoc / python-docx，此时该记 SKIP 而不是红")
        if (self.mod._v3(self.mod._pandoc_version()) != "3.1.11"
                or self.mod._v3(got_docx) != "1.2.0"):
            self.skipTest("工具链与登记不符 —— 那时走的是 toolchain-drift 分支")
        build_tree(self.root)
        (self.root / "docs" / "report.docx").write_bytes(b"fake")
        builder = self.root / "tools" / "build_report_docx.py"
        builder.parent.mkdir(parents=True, exist_ok=True)
        for body, kind, sev in (
                ("import sys\nsys.exit(0)", "consistent", "ok"),
                ("import sys\nsys.stderr.write('落后 3 节\\n')\nsys.exit(1)",
                 "inconsistent", "fail"),
                ("import sys\nsys.exit(2)", "builder-broken", "fail")):
            builder.write_text(body, encoding="utf-8")
            f = self._docx_finding()
            self.assertEqual((f.kind, f.severity), (kind, sev), f"builder {body!r}")
            if kind == "inconsistent":
                self.assertIn("重新生成", f.message,
                              "报文里要写清楚跑哪条命令能修好")

    def test_missing_docx_artifact_is_skip(self):
        build_tree(self.root)
        self.assertEqual((self._docx_finding().severity, self._docx_finding().kind),
                         ("skip", "missing-artifact"))

    # -- 反控 7：门禁自证（closure） ---------------------------------------- #

    def test_closure_catches_fact_without_site(self):
        build_tree(self.root)
        man = json.loads((self.root / "docs" / "facts.json").read_text(encoding="utf-8"))
        man["facts"]["lonely.fact"] = {"value": 1, "norm": "int", "probe": None}
        (self.root / "docs" / "facts.json").write_text(
            json.dumps(man, ensure_ascii=False), encoding="utf-8")
        f = _find(_results(self.mod, self.root), "fact-without-site")
        self.assertEqual(f.check, "closure")

    def test_closure_catches_unknown_probe(self):
        build_tree(self.root)
        man = json.loads((self.root / "docs" / "facts.json").read_text(encoding="utf-8"))
        man["facts"]["pipeline.agents"]["probe"] = "no.such.probe"
        (self.root / "docs" / "facts.json").write_text(
            json.dumps(man, ensure_ascii=False), encoding="utf-8")
        self.assertTrue(_all_of(_results(self.mod, self.root), "unknown-probe"))

    def test_closure_catches_missing_managed_file(self):
        build_tree(self.root)
        (self.root / "README.md").unlink()
        self.assertEqual(_find(_results(self.mod, self.root), "missing-managed").file,
                         "README.md")

    def test_closure_catches_orphan_and_undeclared_figures(self):
        build_tree(self.root)
        md = self.root / "docs" / "report.md"
        md.write_text(REPORT_MD.replace("figs/fig1.png", "figs/ghost.png"),
                      encoding="utf-8")
        results = _results(self.mod, self.root)
        self.assertTrue(_all_of(results, "missing-figure"), "引用了不存在的图 = 红")
        self.assertTrue(_all_of(results, "orphan-figure"), "生成了没人用 = 黄")

    def test_every_check_ran(self):
        """回归：`run()` 曾把 closure 自己排除在 `seen` 之外，于是自证恒报红。"""
        build_tree(self.root)
        results = _results(self.mod, self.root)
        self.assertEqual(set(results), set(self.mod.CHECKS))
        self.assertEqual(_all_of(results, "check-not-run"), [])

    # -- 归一化：白名单之外宁可取不到值 ------------------------------------ #

    def test_normalization_never_guesses(self):
        d = self.mod.docfacts
        self.assertEqual(d.cn_to_int("六"), 6)
        self.assertEqual(d.cn_to_int("十"), 10)
        self.assertEqual(d.cn_to_int("两"), 2)
        self.assertEqual(d.cn_to_int("二十一"), 21)
        self.assertIsNone(d.cn_to_int("十二万"), "取不到值就报错，别把两句话比成相等")
        self.assertEqual(d.normalize("1,234", "int_thousands"), 1234)
        self.assertEqual(d.normalize_text("7", "cn_or_int"), 7)

    def test_units_are_literal_bound_not_line_bound(self):
        """锚点随内容走：同一个文件里两条 caption 各自成一个可定位单元。"""
        build_tree(self.root)
        units = self.mod.docfacts.units_for(
            self.root / "docs" / "figs" / "make_figs.py", "x.py")[0]
        texts = [u.text for u in units]
        self.assertIn("迷你架构：1,234 条规则", texts)
        self.assertIn("3 Agent 流水线", texts)


if __name__ == "__main__":
    unittest.main()
