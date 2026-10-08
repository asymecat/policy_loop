"""Tests for tools.apply_converge (converge report -> board policy -> policy.31).

Covers the gates that sit between a converge patch and a compiled board policy:
class-permission lookup (own perms plus the `classcommon` inheritance that a
naive parse misses), attribute closure, xperm interval coverage, the symbol /
permission / idempotence gates, and the CIL rendering (whose two traps -- the
keyword is `allowx` not `allowxperm`, and the class name lives inside the
`ioctl` form -- were both found by compiling against the real board policy).
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.apply_converge import (  # noqa: E402
    Board,
    _gate4_verdict,
    _shown,
    _xperm_covered,
    _xperm_intervals,
    collect_neverallow,
    count_assertions,
    gate_idempotent,
    gate_parse,
    gate_perms,
    gate_symbols,
    render_cil,
)

# 一份自洽的小策略：`dir` 自有 add_name/search 等，又经 classcommon 继承 file 的权限。
BOARD_CIL = """\
(common file (ioctl read write create getattr setattr open map))
(class file (execute_no_trans entrypoint))
(class dir (add_name remove_name reparent rmdir search))
(class chr_file (ioctl))
(classcommon file file)
(classcommon dir file)
(classcommon chr_file file)
(type app_domain)
(type other_domain)
(type dev_file)
(type data_file)
(typeattribute file_type)
(typeattributeset file_type (data_file))
(allow app_domain data_file (file (read getattr)))
(allow other_domain file_type (file (write)))
(allowx app_domain dev_file (ioctl chr_file ((0xf50c (range 0xf546 0xf547)))))
"""


def _board():
    return Board(BOARD_CIL, Path("<fixture>"))


def _run_gates(lines, board):
    rules = gate_parse(lines)
    rules = gate_symbols(rules, board)
    rules = gate_perms(rules, board)
    return gate_idempotent(rules, board)


class TestBoardParsing(unittest.TestCase):
    def test_class_perms_include_inherited_common(self):
        """`(class dir (...))` 只列自有权限，继承来的在 `(common file ...)` 里。

        只读前半截会得出 "dir 类没有 getattr" 这种结论 —— 实测踩过。
        """
        b = _board()
        self.assertIn("getattr", b.class_perms["dir"])   # 经 classcommon dir file 继承
        self.assertIn("search", b.class_perms["dir"])    # 自有
        self.assertIn("getattr", b.class_perms["file"])
        self.assertNotIn("search", b.class_perms["file"])

    def test_attribute_closure(self):
        b = _board()
        self.assertIn("file_type", b.closure("data_file"))
        self.assertEqual(b.closure("app_domain"), frozenset({"app_domain"}))

    def test_satisfied_finds_allow_written_on_an_attribute(self):
        """`(allow other_domain file_type ...)` 对成员 data_file 同样成立。

        方向是"具体类型 → 它所属的属性"，因为真实 denial 的 tcontext 永远是具体
        类型，而授权可能写在属性上。反方向（拿属性去问）语义上要求**每个**成员都
        被允许，不是这里要问的问题。
        """
        b = _board()
        self.assertTrue(b.satisfied("other_domain", "data_file", "file", {"write"}))
        self.assertFalse(b.satisfied("other_domain", "data_file", "file", {"read"}))

    def test_neverallow_absent_is_not_an_error(self):
        """板子策略由 policy.31 反编译而来，本就不含 neverallow（编译期断言）。"""
        self.assertEqual(BOARD_CIL.count("(neverallow"), 0)


class TestXperm(unittest.TestCase):
    def test_intervals_flatten_ranges_and_bare_values(self):
        ivals = _xperm_intervals("(0xf50c (range 0xf546 0xf547))")
        self.assertIn((0xF50C, 0xF50C), ivals)
        self.assertIn((0xF546, 0xF547), ivals)

    def test_covered_uses_ranges(self):
        ivals = _xperm_intervals("(0xf50c (range 0xf546 0xf547))")
        self.assertTrue(_xperm_covered(ivals, 0xF547))
        self.assertTrue(_xperm_covered(ivals, 0xF50C))
        self.assertFalse(_xperm_covered(ivals, 0x9999))

    def test_xperm_satisfied_through_range(self):
        """实测：板子上的 `(range 0x6201 0x6203) 0x6206` 覆盖了 0x6206。"""
        b = _board()
        self.assertTrue(b.xperm_satisfied("app_domain", "dev_file", "chr_file", {"0xf547"}))
        self.assertFalse(b.xperm_satisfied("app_domain", "dev_file", "chr_file", {"0x9999"}))


class TestGates(unittest.TestCase):
    def test_parse_rejects_non_allow(self):
        rules = gate_parse(["type_transition foo bar;"])
        self.assertEqual(rules[0]["verdict"], "rejected")
        self.assertEqual(rules[0]["gate"], "parse")

    def test_symbol_gate_rejects_unknown_type(self):
        r = _run_gates(["allow ghost_domain data_file:file { read };"], _board())[0]
        self.assertEqual(r["verdict"], "rejected")
        self.assertEqual(r["gate"], "symbols")

    def test_perm_gate_rejects_perm_of_another_class(self):
        """`add_name` 是 dir 的权限；写成 file 类是上游语料与板子的版本差。"""
        r = _run_gates(["allow app_domain data_file:file { add_name };"], _board())[0]
        self.assertEqual(r["verdict"], "rejected")
        self.assertEqual(r["gate"], "perms")

    def test_idempotent_skips_already_allowed(self):
        r = _run_gates(["allow app_domain data_file:file { read };"], _board())[0]
        self.assertEqual(r["verdict"], "already_satisfied")

    def test_idempotent_skips_xperm_covered_by_range(self):
        r = _run_gates(
            ["allowxperm app_domain dev_file:chr_file ioctl { 0xf547 };"], _board())[0]
        self.assertEqual(r["verdict"], "already_satisfied")

    def test_new_rule_survives_all_gates(self):
        r = _run_gates(["allow app_domain data_file:file { write };"], _board())[0]
        self.assertEqual(r["verdict"], "emit")


class TestRenderCil(unittest.TestCase):
    def test_allow_renders_as_cil_list(self):
        rules = _run_gates(["allow app_domain data_file:file { read write };"], _board())
        rules[0]["verdict"] = "emit"
        self.assertEqual(render_cil(rules),
                         "(allow app_domain data_file (file (read write)))\n")

    def test_allowx_keyword_is_allowx_not_allowxperm(self):
        """CIL 关键字是 `allowx`；写成 `allowxperm` 会 `Unknown keyword allowxperm`。"""
        rules = _run_gates(
            ["allowxperm app_domain dev_file:chr_file ioctl { 0x9999 };"], _board())
        rules[0]["verdict"] = "emit"
        out = render_cil(rules)
        self.assertIn("(allowx app_domain dev_file ", out)
        self.assertNotIn("allowxperm", out)

    def test_allowx_class_sits_inside_ioctl_form(self):
        """括号结构是 `(allowx S T (ioctl 类 (xperm)))` —— 类名不在第三参数位。"""
        rules = _run_gates(
            ["allowxperm app_domain dev_file:chr_file ioctl { 0x9999 };"], _board())
        rules[0]["verdict"] = "emit"
        self.assertEqual(render_cil(rules),
                         "(allowx app_domain dev_file (ioctl chr_file (0x9999)))\n")


class TestCollectNeverallow(unittest.TestCase):
    """源树 neverallow → 可注入板子 CIL 的断言。

    这是让门 4 从「可编译性检查」变成「红线检查」的那一步：板子 CIL 由二进制
    反编译而来，而 neverallow 是编译期断言、不落盘，所以 `secilc` 编译一份不含
    断言的策略，无论后面再堆几道门都不可能发现越权。只有当待编译的 CIL 里重新
    写出断言，编译器才会检查它们。

    翻译不出来的形态必须**跳过并计数**，不能近似：把红线重述得比原版更窄，
    比没有红线更糟——它看起来像一道通过了的检查。
    """

    def _collect(self, te: str, spt: str = ""):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "policy.te").write_text(te, encoding="utf-8")
            if spt:
                (Path(d) / "glb_def.spt").write_text(spt, encoding="utf-8")
            return collect_neverallow(Path(d), _board())

    def test_plain_statement_is_translated(self):
        lines, stats = self._collect(
            "neverallow app_domain data_file:file { read };\n")
        self.assertEqual(lines, ["(neverallow app_domain data_file (file (read)))"])
        self.assertEqual(stats, {})

    def test_wrapped_statement_is_joined_first(self):
        """40 条上游规则跨行书写；按行读只会得到谁都匹配不上的碎片。"""
        lines, stats = self._collect(
            "neverallow app_domain data_file:file { read\n   write };\n")
        self.assertEqual(
            lines, ["(neverallow app_domain data_file (file (read write)))"])
        self.assertEqual(stats, {})

    def test_source_list_becomes_a_set_expression(self):
        """`{ a b }` 在 CIL 里就是 `(or (a) (b))` —— 精确，不是近似。

        表达式不能直接写进 neverallow 的 src 位（CIL 只收**类型或属性名**），
        所以先合成一个属性再引用它。声明必须一起注入，否则 secilc 报未定义。
        """
        lines, stats = self._collect(
            "neverallow { app_domain other_domain } data_file:file { read };\n")
        self.assertEqual(lines, [
            "(typeattribute pl_na_set_1)",
            "(typeattributeset pl_na_set_1 (or (app_domain) (other_domain)))",
            "(neverallow pl_na_set_1 data_file (file (read)))",
        ])
        self.assertEqual(stats, {})

    def test_difference_uses_and_not(self):
        """`{ a -b }` 是差集，OH 里到处都是（属性集减掉一个例外）。"""
        lines, _ = self._collect(
            "neverallow { app_domain -other_domain } data_file:file { read };\n")
        self.assertEqual(lines[1],
                         "(typeattributeset pl_na_set_1 "
                         "(and (app_domain) (not (other_domain))))")

    def test_more_than_two_operands_are_folded(self):
        """★ `(or (a) (b) (c))` 会被 secilc 判成 Bad typeattributeset statement
        —— `and`/`or` 只收两个操作数，三元素以上的列表必须折成二叉树。"""
        lines, _ = self._collect(
            "neverallow { app_domain other_domain file_type } data_file:file { read };\n")
        self.assertEqual(lines[1],
                         "(typeattributeset pl_na_set_1 "
                         "(or (app_domain) (or (other_domain) (file_type))))")

    def test_wildcard_type_becomes_all(self):
        """`(all)` 只能出现在 typeattributeset 里；写进规则位置会
        `Invalid syntax Bad allow rule`（这条曾把 `self` 误判成"CIL 不支持"）。"""
        lines, _ = self._collect("neverallow * data_file:file { read };\n")
        self.assertEqual(lines[1], "(typeattributeset pl_na_set_1 (all))")

    def test_negated_attribute_and_negated_set(self):
        lines, _ = self._collect("neverallow ~app_domain data_file:file { read };\n")
        self.assertEqual(lines[1], "(typeattributeset pl_na_set_1 (not (app_domain)))")
        lines, _ = self._collect(
            "neverallow ~{ app_domain other_domain } data_file:file { read };\n")
        self.assertEqual(lines[1],
                         "(typeattributeset pl_na_set_1 "
                         "(not (or (app_domain) (other_domain))))")

    def test_self_target_uses_the_cil_keyword(self):
        """`self` 是 CIL 自己的关键字，照写即可 —— 不要摊成 x → x 的笛卡尔积。"""
        lines, stats = self._collect("neverallow app_domain self:file { read };\n")
        self.assertEqual(lines, ["(neverallow app_domain self (file (read)))"])
        self.assertEqual(stats, {})

    def test_source_self_is_skipped(self):
        """.te 的 self 只在目标位有意义；源位写 self 没有语义可依，猜不得。"""
        lines, stats = self._collect("neverallow self data_file:file { read };\n")
        self.assertEqual(lines, [])
        self.assertEqual(stats, {"self 出现在源位置（.te 语法里没有这个写法）": 1})

    def test_negated_perms_complement_over_the_board_table(self):
        """权限位没有 CIL 表达式，只能按**板子**该类的权限表求补。

        用源树的权限表来补会把版本差当成新权限，补出来的红线比原版更宽。
        板子 file 类 = common file + class file 自己的（见 BOARD_CIL）。
        """
        lines, stats = self._collect(
            "neverallow app_domain data_file:file ~{ read };\n")
        self.assertEqual(lines, [
            "(neverallow app_domain data_file "
            "(file (create entrypoint execute_no_trans getattr ioctl map open "
            "setattr write)))"])
        self.assertEqual(stats, {})

    def test_wildcard_perms_expand_to_the_board_table(self):
        lines, _ = self._collect("neverallow app_domain data_file:file *;\n")
        self.assertIn("read", lines[0])
        self.assertIn("getattr", lines[0])     # 经 classcommon 继承自 common file
        self.assertNotIn("search", lines[0])   # search 是 dir 的，不在 file 上

    def test_unknown_symbol_is_skipped(self):
        lines, stats = self._collect(
            "neverallow no_such_domain data_file:file { read };\n")
        self.assertEqual(lines, [])
        self.assertEqual(stats, {"类型/属性不在板子策略中（板上空转）": 1})

    def test_vacuous_symbol_is_dropped_from_a_list(self):
        """板上没有的符号在**集合里**也是空转，丢掉它断言强度不变 —— 但这条
        语句本身不该被丢掉（正项还剩一个）。"""
        lines, _ = self._collect(
            "neverallow { no_such_domain app_domain } data_file:file { read };\n")
        self.assertEqual(lines, ["(neverallow app_domain data_file (file (read)))"])

    def test_class_absent_from_board_is_skipped(self):
        lines, stats = self._collect(
            "neverallow app_domain data_file:no_such_class { read };\n")
        self.assertEqual(lines, [])
        self.assertEqual(stats, {"类不在板子策略中": 1})

    def test_perm_of_another_class_is_skipped(self):
        """`add_name` 是 dir 的权限，不是 file 的；注入会让 secilc 直接报错。"""
        lines, stats = self._collect(
            "neverallow app_domain data_file:file { add_name };\n")
        self.assertEqual(lines, [])
        self.assertEqual(stats, {"权限名不适用于该类的板子策略": 1})

    def test_macro_statement_is_skipped(self):
        lines, stats = self._collect(
            "neverallow debug_only(`app_domain') data_file:file { read };\n")
        self.assertEqual(lines, [])
        self.assertEqual(stats, {"含宏/条件表达式": 1})

    def test_xperm_statement_uses_neverallowx(self):
        lines, _ = self._collect(
            "neverallowxperm app_domain dev_file:chr_file ioctl { 0xf50c };\n")
        self.assertEqual(
            lines, ["(neverallowx app_domain dev_file (ioctl chr_file ((0xf50c))))"])

    def test_xperm_bare_value_without_braces(self):
        """上游有 `neverallowxperm A B:chr_file ioctl 0x1234;` 这种不带花括号的写法。"""
        lines, _ = self._collect(
            "neverallowxperm app_domain dev_file:chr_file ioctl 0xf50c;\n")
        self.assertEqual(
            lines, ["(neverallowx app_domain dev_file (ioctl chr_file ((0xf50c))))"])

    def test_xperm_complement_becomes_ranges(self):
        """CIL 的权限表达式不认 `~`（实测 `permissionx value ~ not valid number`），
        但支持 `(range lo hi)`；16 位空间上挖掉 n 个值最多剩 n+1 段区间。"""
        lines, stats = self._collect(
            "neverallowxperm app_domain dev_file:chr_file ioctl ~{ 0xf50c };\n")
        self.assertEqual(lines, [
            "(neverallowx app_domain dev_file "
            "(ioctl chr_file (((range 0x0000 0xf50b) (range 0xf50d 0xffff)))))"])
        self.assertEqual(stats, {})

    def test_xperm_complement_of_zero_keeps_the_head(self):
        lines, _ = self._collect(
            "neverallowxperm app_domain dev_file:chr_file ioctl ~{ 0x0000 };\n")
        self.assertIn("(range 0x0001 0xffff)", lines[0])

    def test_xperm_32bit_command_is_masked_like_the_te_path(self):
        """★ `.te` 那条路本来就把命令号截成 16 位（`policy_define.c:1973,1993`
        都是 `(uint16_t) strtoul(...)`），CIL 超 0xFFFF 直接报错
        （`cil_post.c:1052`）。所以 `& 0xffff` 是源树语义，不截反而编译不过 ——
        但截了几条要报出来。"""
        lines, stats = self._collect(
            "neverallowxperm app_domain dev_file:chr_file ioctl { 0x400c620e };\n")
        self.assertEqual(
            lines, ["(neverallowx app_domain dev_file (ioctl chr_file ((0x620e))))"])
        self.assertEqual(stats, {"xperm: 32 位命令号按源树语义截成 16 位": 1})

    def test_xperm_class_list_fans_out(self):
        lines, _ = self._collect(
            "neverallowxperm app_domain dev_file:{ chr_file file } ioctl { 0xf50c };\n")
        self.assertEqual(len(lines), 2)
        self.assertIn("ioctl chr_file", lines[0])
        self.assertIn("ioctl file", lines[1])

    def test_macro_symbol_list_is_expanded(self):
        """OH 的 neverallow 大量引用 `glb_te_def.spt` 里的符号列表宏；
        不展开它们只能以"符号不在板子上"跳过，而它们在板上是真实红线。

        `system_domain` 那种宏展开出来是真的属性名 —— 这里用的是同样的形状。
        """
        lines, stats = self._collect(
            "neverallow never_dom data_file:file { read };\n",
            spt="define(`never_dom', `app_domain other_domain')\n")
        self.assertEqual(lines, [
            "(typeattribute pl_na_set_1)",
            "(typeattributeset pl_na_set_1 (or (app_domain) (other_domain)))",
            "(neverallow pl_na_set_1 data_file (file (read)))",
        ])
        self.assertEqual(stats, {})

    def test_macro_class_and_perm_sets_are_expanded(self):
        """类集宏（`file_class_set`）与权限集宏（`never_write_dir`）同样要展开，
        而且宏里还能再套宏。"""
        lines, _ = self._collect(
            "neverallow app_domain data_file:{ devfile_class_set } { never_rd };\n",
            spt="define(`devfile_class_set', `file chr_file')\n"
                "define(`never_rd', `read getattr')\n")
        self.assertEqual(lines, [
            "(neverallow app_domain data_file (file (getattr read)))",
            "(neverallow app_domain data_file (chr_file (getattr read)))",
        ])

    def test_statement_template_macro_is_not_treated_as_a_set(self):
        """含 `$1`/`(`的宏是**语句模板**（`binder_call` 那种），展开出来不是
        符号列表；收进来只会得到一堆语法碎片。"""
        lines, stats = self._collect(
            "neverallow tpl_macro data_file:file { read };\n",
            spt="define(`tpl_macro', `$1 other_domain')\n")
        self.assertEqual(lines, [])
        self.assertEqual(stats, {"类型/属性不在板子策略中（板上空转）": 1})

    def test_count_assertions_ignores_synthetic_declarations(self):
        """注入行里混着合成属性的声明；只数真断言。`(neverallowx` 也要算进去。"""
        self.assertEqual(count_assertions([
            "(typeattribute pl_na_set_1)",
            "(typeattributeset pl_na_set_1 (or (a) (b)))",
            "(neverallow pl_na_set_1 data_file (file (read)))",
            "(neverallowx a b (ioctl chr_file ((0xf50c))))",
        ]), 2)

    def test_identical_statements_are_injected_once(self):
        lines, stats = self._collect(
            "neverallow app_domain data_file:file { read };\n"
            "neverallow app_domain data_file:file { read };\n")
        self.assertEqual(len(lines), 1)
        self.assertEqual(stats, {"重复（已去重）": 1})

    def test_perm_order_does_not_produce_two_assertions(self):
        lines, _ = self._collect(
            "neverallow app_domain data_file:file { read write };\n"
            "neverallow app_domain data_file:file { write read };\n")
        self.assertEqual(len(lines), 1)


class TestGate4Verdict(unittest.TestCase):
    """片段头里的门 4 结论必须由**编译结果**决定。

    头是编译前拼的，原先无条件写"secilc 编译通过"。撞红线时这句就成了假话，
    而片段是会被拷进策略树、也会被人单独阅读的东西。
    """

    def test_passed_says_passed(self):
        self.assertIn("通过", _gate4_verdict(True))
        self.assertNotIn("失败", _gate4_verdict(True))

    def test_failed_says_not_landable(self):
        out = _gate4_verdict(False)
        self.assertIn("失败", out)
        self.assertIn("不可落地", out)

    def test_not_built_admits_the_red_lines_were_never_checked(self):
        """`ok is None`（--no-build）不能说"通过"——红线根本没查过。"""
        out = _gate4_verdict(None)
        self.assertNotIn("通过", out)
        self.assertIn("未被检查过", out)


class TestShown(unittest.TestCase):
    def test_absolute_path_outside_repo_does_not_raise(self):
        """`--out-cil /tmp/x.cil` 曾经在 *print* 里抛 ValueError，
        而此时 CIL 片段已经写盘 —— 崩溃留下一个半成品。"""
        self.assertEqual(_shown(Path("/tmp/pl_x.cil")), "/tmp/pl_x.cil")

    def test_repo_path_is_relative(self):
        self.assertEqual(_shown(ROOT / "README.md"), "README.md")


if __name__ == "__main__":
    unittest.main()
