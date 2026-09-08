"""Corpus tooling for the real OpenHarmony sepolicy fetched from upstream.

Scans the (sparse-cloned) `security_selinux_adapter/sepolicy` tree and reports:

* corpus size          : files / lines / statement kinds
* denial evidence      : how many `# avc: denied ...` comments exist, and on
                         how many files
* OH-specific classes  : distribution of object classes mentioned in allow rules

Usage:
    python -m policy_loop.eval.corpus [--root data/raw/oh-selinux/sepolicy]
                                      [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from policy_loop.policy import PolicyIndex

_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "raw" / "oh-selinux" / "sepolicy"

_STMT_RE = re.compile(r"^\s*(?P<kind>allow|allowxperm|neverallow|neverallowxperm"
                      r"|type_transition|type_change|type_member|type\b"
                      r"|attribute\b|domain_trans|rattribute\b|bool\b|genfscon\b"
                      r"|[A-Za-z_][A-Za-z0-9_]*\s*\()")
_DENIAL_COMMENT_RE = re.compile(r"\bavc\s*:\s*denied", re.IGNORECASE)
# capture tclass token from an allow rule for class distribution
_TCLASS_RE = re.compile(r":\s*([A-Za-z_][A-Za-z0-9_]*)\s*[;\s{]")


def iter_te(root: Path):
    for te in sorted(root.rglob("*.te")):
        yield te


def scan(root: Path) -> dict:
    stats = {
        "root": str(root),
        "files": 0,
        "lines": 0,
        "files_with_denial_comments": 0,
        "denial_comments": 0,
        "statement_kinds": Counter(),
        "rules_indexed": 0,
        "types": 0,
        "attributes": 0,
        "skipped_statements": 0,
        "class_counts": Counter(),
    }

    idx = PolicyIndex()
    for te in iter_te(root):
        text = te.read_text(encoding="utf-8", errors="replace")
        stats["files"] += 1
        lines = text.splitlines()
        stats["lines"] += len(lines)
        file_has_denial = False
        for line in lines:
            s = line.strip()
            if s.startswith("#"):
                if _DENIAL_COMMENT_RE.search(line):
                    stats["denial_comments"] += 1
                    file_has_denial = True
                continue
            if not s or s.startswith("//"):
                continue
            m = _STMT_RE.match(s)
            if m:
                stats["statement_kinds"][m.group("kind")] += 1
            tc = _TCLASS_RE.search(s)
            if tc and s.startswith(("allow ", "allowxperm ")):
                stats["class_counts"][tc.group(1)] += 1
        if file_has_denial:
            stats["files_with_denial_comments"] += 1
        idx.load_text(text, source=str(te))

    summary = idx.summary()
    stats["rules_indexed"] = summary["rules"]
    stats["types"] = summary["types"]
    stats["attributes"] = summary["attributes"]
    stats["skipped_statements"] = summary["skipped_statements"]
    # statement kinds -> plain dict for JSON
    stats["statement_kinds"] = dict(stats["statement_kinds"])
    stats["class_counts"] = dict(
        stats["class_counts"].most_common()
    )
    return stats


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan OpenHarmony sepolicy corpus")
    ap.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    ap.add_argument("--json", type=Path, default=None, help="write report json")
    args = ap.parse_args(argv)

    if not args.root.exists():
        print(f"corpus not found: {args.root} "
              f"(run: git clone --depth 1 --sparse "
              f"https://gitee.com/openharmony/security_selinux_adapter.git "
              f"data/raw/oh-selinux)")
        return 1

    stats = scan(args.root)

    print(f"root               : {stats['root']}")
    print(f".te files          : {stats['files']}")
    print(f"lines              : {stats['lines']}")
    print(f"denial comments    : {stats['denial_comments']} "
          f"(in {stats['files_with_denial_comments']} files)")
    print(f"rules indexed      : {stats['rules_indexed']}")
    print(f"types indexed      : {stats['types']}")
    print(f"attributes         : {stats['attributes']}")
    print(f"skipped statements : {stats['skipped_statements']}")
    print("statement kinds    :", json.dumps(stats["statement_kinds"],
                                             ensure_ascii=False))
    print("top object classes :",
          json.dumps(dict(list(stats["class_counts"].items())[:25]),
                     ensure_ascii=False))
    print("skipped ratio (allow-like unsupported) : "
          f"{stats['skipped_statements'] / max(stats['lines'], 1):.4f}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nreport written -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
