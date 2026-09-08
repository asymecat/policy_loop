"""Extract denial -> fix pairs from real OpenHarmony sepolicy.

OpenHarmony upstream policy files record real AVC denials as comments directly
above the rule that fixed them, e.g.::

    # avc: denied { ioctl } for pid=7881 ... scontext=u:r:faultloggerd:s0 ...
    # avc: denied { open }  for pid=7881 ...
    allow faultloggerd dev_pdump:chr_file { ioctl open read };

This tool pairs each `# avc: denied` comment block with the allow/allowxperm
statement that follows it, producing a **golden evaluation set** of
(denial -> correct least-privilege fix) from real-world evidence.

Usage:
    python -m policy_loop.eval.extract [--root ...] [--out data/eval/golden.jsonl]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from policy_loop.denial import parse as parse_denials

_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "raw" / "oh-selinux" / "sepolicy"
_DEFAULT_OUT = Path(__file__).resolve().parents[2] / "data" / "eval" / "golden.jsonl"

_FIX_KIND_RE = re.compile(r"^\s*(allowxperm|allow|neverallowxperm|neverallow)\b")
_COMMENT_RE = re.compile(r"^\s*#")


def _denials_from(lines: list) -> list:
    out: list = []
    for c in lines:
        out.extend(parse_denials(c))
    return out


def _emit(golden: list, stats: dict, rel: str, rule_line: int,
          rule_kind: str, rule_raw: str, denials: list,
          direction: str) -> None:
    if not denials:
        return
    golden.append({
        "file": rel,
        "rule_line": rule_line,
        "rule_kind": rule_kind,
        "rule_raw": rule_raw,
        "direction": direction,          # "rule_first" | "comment_first"
        "denials": [d.to_dict() for d in denials],
    })
    stats["golden_pairs"] += 1
    stats["golden_denials"] += len(denials)


def extract(root: Path) -> dict:
    """Scan *root* and return {golden: [...], stats: {...}}.

    Upstream files use BOTH layouts::

        # avc: denied {...}            # comment-first (fix below)
        allow X Y:cls { perm };

        allow X Y:cls { perm };        # rule-first (denial evidence below)
        # avc: denied {...}

    We pair an allow/allowxperm rule with an adjacent denial-comment block in
    either direction.
    """
    golden: list = []
    stats = {
        "files": 0,
        "denial_comment_lines": 0,
        "golden_pairs": 0,
        "golden_denials": 0,
        "unpaired_comment_blocks": 0,
    }

    for te in sorted(root.rglob("*.te")):
        stats["files"] += 1
        rel = str(te.relative_to(root))
        pending_comments: list = []     # comment-first buffer
        last_rule = None                # (line, kind, raw) rule-first candidate
        last_rule_consumed = True

        for lineno, line in enumerate(te.read_text(
                encoding="utf-8", errors="replace").splitlines(), 1):
            s = line.strip()
            if _COMMENT_RE.match(s):
                if re.search(r"\bavc\s*:\s*denied", s, re.IGNORECASE):
                    stats["denial_comment_lines"] += 1
                    if last_rule is not None and not last_rule_consumed:
                        # rule-first: this rule (just above) is the fix
                        _emit(golden, stats, rel, last_rule[0], last_rule[1],
                              last_rule[2], _denials_from([s]),
                              direction="rule_first")
                        last_rule_consumed = True
                    else:
                        pending_comments.append(s)
                continue

            if not s:
                continue

            m = _FIX_KIND_RE.match(s)
            if m:
                kind = m.group(1)
                if kind in ("allow", "allowxperm"):
                    if pending_comments:
                        # comment-first: this rule fixes the pending denials
                        _emit(golden, stats, rel, lineno, kind, s,
                              _denials_from(pending_comments),
                              direction="comment_first")
                        pending_comments = []
                        last_rule = None
                        last_rule_consumed = True
                    else:
                        last_rule = (lineno, kind, s)
                        last_rule_consumed = False
                else:                    # neverallow etc. -> no pairing
                    pending_comments = []
                    last_rule = None
                    last_rule_consumed = True
                continue

            # any other statement breaks adjacency
            if pending_comments:
                stats["unpaired_comment_blocks"] += 1
            pending_comments = []
            last_rule = None
            last_rule_consumed = True

    return {"golden": golden, "stats": stats}


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract denial->fix golden set")
    ap.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = ap.parse_args(argv)

    if not args.root.exists():
        print(f"corpus not found: {args.root}")
        return 1

    result = extract(args.root)
    stats = result["stats"]
    print(f"files scanned            : {stats['files']}")
    print(f"denial comment lines     : {stats['denial_comment_lines']}")
    print(f"golden pairs (denial->fix): {stats['golden_pairs']}")
    print(f"golden denials (parsed)  : {stats['golden_denials']}")
    print(f"unpaired comment blocks  : {stats['unpaired_comment_blocks']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for g in result["golden"]:
            fh.write(json.dumps(g, ensure_ascii=False) + "\n")
    print(f"golden set written -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
