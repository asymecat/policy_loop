"""Command line for the PLI exporter.

Usage::

    python -m policy_loop.export --policy data/raw/oh-selinux/sepolicy \
        --out build/pli/ohos-rk3568.pli \
        --gzip build/pli/ohos.pli.gz \
        --index-info build/pli/index-info.json

    # verify an existing export is still byte-identical (drift guard)
    python -m policy_loop.export --policy <dir> --out <file> --check

The ``--check`` mode exists so that a change to ``PolicyIndex`` parsing (or to
this exporter) that silently changes the serialized index is caught by CI
rather than discovered as a mystery divergence on the device.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Optional

from policy_loop.policy import load_dir, load_text

from .pli import PLI_VERSION, compute_meta, export_file, export_text

__all__ = ["main"]


def _git_info(path: Path) -> dict:
    """Best-effort git identity of the policy source (never fatal).

    Recorded so a device-side report can be tied back to the exact sepolicy
    revision it was judged against — the index and the firmware's compiled
    ``policy.31`` must come from the same tree for a verdict to be meaningful.
    """
    def _run(*args):
        try:
            p = subprocess.run(["git", "-C", str(path), *args],
                               capture_output=True, text=True, timeout=5)
            return p.stdout.strip() if p.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    sha = _run("rev-parse", "HEAD")
    if not sha:
        return {}
    return {
        "git_sha": sha,
        "git_short": sha[:12],
        "git_dirty": bool(_run("status", "--porcelain")),
        "git_root": _run("rev-parse", "--show-toplevel"),
    }


def _existing_gen_time(path: Path) -> Optional[str]:
    """The ``gen=`` stamp of an existing PLI file, or None.

    ``--check`` re-exports the index and compares byte for byte, but the export
    stamps the current time into ``@src`` -- so without this, every comparison
    after the first second reports drift, and the guard degenerates into a
    no-op that "always finds a difference". Reusing the stored stamp makes the
    comparison isolate what it is meant to isolate: the *content*.
    """
    try:
        head = path.read_text(encoding="utf-8").splitlines()[:6]
    except (OSError, UnicodeDecodeError):
        return None
    for line in head:
        if line.startswith("@src "):
            for field in line.split():
                if field.startswith("gen="):
                    return field[len("gen="):]
    return None


def _load_index(policy: str):
    p = Path(policy)
    if p.is_dir():
        return load_dir(p)
    if p.exists():
        return load_text(p.read_text(encoding="utf-8", errors="replace"),
                         source=str(p))
    raise FileNotFoundError(f"policy not found: {policy}")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m policy_loop.export",
        description="Export a policy_loop PolicyIndex to PLI v1 text "
                    "for on-device lookup")
    ap.add_argument("--policy", required=True,
                    help="sepolicy dir or single .te file to index")
    ap.add_argument("--out", type=Path,
                    help="write PLI text here")
    ap.add_argument("--gzip", type=Path,
                    help="also write a gzipped copy (shorter serial transfer)")
    ap.add_argument("--index-info", type=Path,
                    help="write a JSON summary (meta + git identity)")
    ap.add_argument("--check", action="store_true",
                    help="compare with --out instead of writing; "
                         "exit 1 on any difference")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if not args.out and not args.check:
        ap.error("provide --out <file> (or --check with --out)")

    index = _load_index(args.policy)
    meta, known, classes, perms = compute_meta(index)
    git = _git_info(Path(args.policy))

    label = args.policy
    if git.get("git_short"):
        label += "@" + git["git_short"]
        if git.get("git_dirty"):
            label += "+dirty"

    if args.check:
        if not args.out or not args.out.exists():
            ap.error("--check needs an existing --out file")
        current = export_text(index, src_label=label,
                              gen_time=_existing_gen_time(args.out))
        previous = args.out.read_text(encoding="utf-8")
        if current == previous:
            if not args.quiet:
                print(f"[export] OK — {args.out} is byte-identical "
                      f"(rules={meta['rules']})")
            return 0
        cur_lines = current.splitlines()
        old_lines = previous.splitlines()
        diff_at = next((i for i, (a, b) in enumerate(zip(old_lines, cur_lines))
                        if a != b), min(len(old_lines), len(cur_lines)))
        print(f"[export] MISMATCH at line {diff_at + 1}: "
              f"{len(old_lines)} -> {len(cur_lines)} lines")
        for i in range(max(0, diff_at - 1), min(diff_at + 3, len(cur_lines))):
            old = old_lines[i] if i < len(old_lines) else "<missing>"
            new = cur_lines[i] if i < len(cur_lines) else "<missing>"
            mark = "  " if old == new else "!!"
            print(f"{mark} - {old[:120]}")
            print(f"{mark} + {new[:120]}")
        return 1

    written_meta = export_file(index, args.out, src_label=label,
                               gzip_path=args.gzip)
    assert written_meta == meta

    info = {
        "pli_version": PLI_VERSION,
        "source": label,
        "policy_path": str(Path(args.policy).resolve()),
        "out": str(args.out),
        "gzip": str(args.gzip) if args.gzip else None,
        "meta": meta,
        "known_tokens": len(known),
        "known_classes": sorted(classes),
        "known_classes_count": len(classes),
        "perms_count": len(perms),
        "te_sources": len(index._sources),
        **git,
    }
    if args.index_info:
        args.index_info.parent.mkdir(parents=True, exist_ok=True)
        args.index_info.write_text(
            json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")

    if not args.quiet:
        size = args.out.stat().st_size
        print(f"[export] {args.out}  {size / 1024:.1f} KB  "
              f"rules={meta['rules']} types={meta['types']} "
              f"classes={meta['classes']} known={meta['known']} "
              f"skipped={meta['skipped']}")
        if args.gzip:
            gz = args.gzip.stat().st_size
            print(f"[export] {args.gzip}  {gz / 1024:.1f} KB "
                  f"({100 * gz / size:.0f}% of text)")
        if args.index_info:
            print(f"[export] index info -> {args.index_info}")
    return 0
