"""两份「工具造成」清单必须一致 —— 用测试守着，不靠记性。

同一件事（一条 denial 是我们的工具造成的、还是被测固件的缺陷）要在两个地方
分别判一次，因为它们跑在两个进程里：

    PC 侧   tools/board_bridge.py::TOOL_DOMAINS
    板端    pl_console/.../napi_init.cpp::kToolDomains

两边回答的是同一个问题、看的是同一份数据，而演示时**两种答案会同屏并列**，
所以一条域加进一份、漏了另一份，就会有一半界面在安静地把工具足迹算成板子缺陷。

这不是假设：`pl_collector` 曾经两份都漏，探针自己造的那条
`pl_collector -> data_local:dir` 一直被标成「板子自带」，违反了 docs/report.md
承诺的「工具造成的 denial 会明确标注，不冒充分析结果」。C++ 那份的注释里已经写着
两份「必须保持一致」—— 这个测试的作用就是让那句话是**真的**，而不是被记住的。

板端源码在隔壁工程里（不在本仓）。它通常是 ~/ohos_audit/pl_console；
换地方就设 PL_CONSOLE_SRC。找不到时**跳过并出声**，不装作通过。
"""

import importlib.util
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CONSOLE_SRC = Path(
    os.environ.get("PL_CONSOLE_SRC") or (Path.home() / "ohos_audit" / "pl_console")
)
NAPI = CONSOLE_SRC / "entry" / "src" / "main" / "cpp" / "napi_init.cpp"


def load_bridge():
    """导入 tools/board_bridge.py（tools/ 不是包，走 spec 加载）。"""
    path = ROOT / "tools" / "board_bridge.py"
    spec = importlib.util.spec_from_file_location("board_bridge_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cpp_domains(text):
    """取出 `kToolDomains = { ... };` 花括号里的字符串字面量。

    按括号配对数到收尾那个 `}`，再把注释剥掉 —— 注释里有反引号和路径，
    直接对全文抓引号会抓进注释里的内容。
    """
    open_brace = text.index("{", text.index("kToolDomains"))
    depth, i = 0, open_brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if i >= len(text):
        raise AssertionError("kToolDomains 的 { 没有配对的 } —— 文件结构变了？")

    body = text[open_brace + 1 : i]
    body = re.sub(r"//[^\n]*", "", body)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return set(re.findall(r'"([^"]*)"', body))


class TestToolDomainsSync(unittest.TestCase):
    def test_python_side_parses(self):
        """Python 那份能读出来、且非空（否则下面的比对是拿空集对空集）。"""
        domains = load_bridge().TOOL_DOMAINS
        self.assertGreater(len(domains), 0, "TOOL_DOMAINS 读出来是空的")
        self.assertTrue(all(d == d.strip() for d in domains))

    def test_two_lists_are_identical(self):
        if not NAPI.is_file():
            self.skipTest(
                f"板端源码不在 {NAPI}；设 PL_CONSOLE_SRC 指向 pl_console 工程再跑。"
                "（跳过 ≠ 一致，只是这次没查。）"
            )

        py = load_bridge().TOOL_DOMAINS
        cpp = cpp_domains(NAPI.read_text(encoding="utf-8"))

        # 解析器坏掉会返回空集，那会伪装成"清单空了"。先把这个可能性掐掉。
        self.assertGreater(
            len(cpp), 0, "C++ 侧解析出 0 个域名 —— 多半是解析器坏了，不是清单空了"
        )

        only_py = sorted(py - cpp)
        only_cpp = sorted(cpp - py)
        self.assertEqual(
            (only_py, only_cpp),
            ([], []),
            "两份清单漂移了：\n"
            f"  只在 board_bridge.py（PC 侧）: {only_py}\n"
            f"  只在 napi_init.cpp（板端）:    {only_cpp}\n"
            "两边都要加，否则同一个域在 PC 和板端会得到相反的结论。",
        )


if __name__ == "__main__":
    unittest.main()
