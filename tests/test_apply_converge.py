"""Tests for tools.apply_converge (converge report -> board policy -> policy.31).

Covers the gates that sit between a converge patch and a compiled board policy:
class-permission lookup (own perms plus the `classcommon` inheritance that a
naive parse misses), attribute closure, xperm interval coverage, the symbol /
permission / idempotence gates, and the CIL rendering (whose two traps -- the
keyword is `allowx` not `allowxperm`, and the class name lives inside the
`ioctl` form -- were both found by compiling against the real board policy).
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.apply_converge import (  # noqa: E402
    Board,
    _xperm_covered,
    _xperm_intervals,
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


if __name__ == "__main__":
    unittest.main()
