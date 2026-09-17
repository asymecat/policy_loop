"""One denial, answered: the host half of `denial_check --explain`.

The device-side C++ component answers a single `avc: denied` line from the PLI
index. This is the same question put to the Python engine, returning the same
JSON object, so the two can be compared with `diff` rather than field by field
(see tests/diff_device.py, mode `explain`).

The construction mirrors `pl_converge.cpp:ExplainDenial` deliberately: take the
first denial in the text, run the *full* six-agent pipeline on it, and report
what came out. The batch path (converge.py) shortcuts obviously-noise cases with
a cheap query; this does not, because the answer a developer wants for one line
is the one the pipeline would give it, guards and all.

Deterministic, stdlib-only. Never writes policy.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from policy_loop.agents import Orchestrator
from policy_loop.denial import parse as parse_denials
from policy_loop.policy import load
from policy_loop.policy.cross_layer import LAYER_LABEL


def _token(value: Optional[str]) -> str:
    """A verdict field as the explanation and the patch spell it.

    An absent field stays None in `case.policy_verdict` -- PolicyAgent keeps the
    Optional -- but the same object's `explanation` renders it as the literal
    token ``None`` the moment it is formatted, and the patch text does the same.
    C++ `BuildVerdict` has no Optional to keep and stores that literal outright.

    So the JSON carries the rendered token rather than null: a `null` sitting
    next to an explanation sentence that says "None" would be the confusing
    option, and it is the one thing the two sides could not agree on.
    """
    return "None" if value is None else str(value)


def explain(text: str, index=None, cross_layer: bool = False) -> Optional[dict]:
    """Explain the first denial in *text*; None if it holds no denial.

    *index* must not be None: every field below except the parsed record is a
    question put to the policy, and answering them without one would be
    guessing.

    *cross_layer* adds the application-layer view under its own key. Off by
    default, and deliberately so: this object is the host half of
    ``denial_check --explain`` (``tests/diff_device.py`` compares the two key
    by key, and the device carries no ``@hap`` table to fill that key from), so
    the default must stay exactly what the device emits.
    """
    records = parse_denials(text)
    if not records:
        return None
    first = records[0]

    case = Orchestrator(index=index).analyze(first.raw)
    v = case.policy_verdict or {}
    if not v:
        return None

    requested = v["requested_perms"]
    granted = v["granted_perms"]
    ioctl = v.get("ioctl") or {}
    recommended = case.recommended or {}

    result = {
        "classification": case.classification,
        "cls": _token(v["cls"]),
        "explanation": case.explanation,
        "granted": granted,
        # Same collapse the device makes: a denial either carried a command
        # number or it did not.
        "ioctl": ioctl.get("cmd") or None,
        "missing": sorted(set(requested) - set(granted)),
        "needs_human": bool(case.needs_human),
        "patch": case.patch,
        "recommended": {"id": recommended.get("id", ""),
                        "title": recommended.get("title", "")},
        "requested": requested,
        "review": (case.review or {}).get("status", ""),
        "src": _token(v["src"]),
        "tgt": _token(v["tgt"]),
        "verify": (case.verify or {}).get("status", ""),
    }
    if cross_layer and case.cross_layer:
        result["cross_layer"] = case.cross_layer
    return result


def to_json(result: dict) -> str:
    """*result* as the device emits it: keys sorted, default separators,
    ensure_ascii=False (the explanation is Chinese), trailing newline."""
    return json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--policy", required=True,
                    help="sepolicy dir or .te file (host index)")
    ap.add_argument("--line", required=True,
                    help="one `avc: denied` log line")
    ap.add_argument("--json", action="store_true",
                    help="emit the JSON object instead of the human summary")
    ap.add_argument("--cross-layer", action="store_true",
                    help="include the application-layer view (APL, shared-domain "
                         "scope, which layer owns the fix). Host-only: it is not "
                         "part of the device's --explain object.")
    args = ap.parse_args(argv)

    index = load(args.policy)
    # The human summary always shows the application-layer answer -- that is
    # the question a developer actually arrived with. The JSON is the device's
    # object, so there the key is opt-in.
    want_cross = args.cross_layer or not args.json
    result = explain(args.line, index=index, cross_layer=want_cross)
    if result is None:
        print("explain: no `avc: denied` record in the given line.",
              file=sys.stderr)
        return 4

    if args.json:
        sys.stdout.write(to_json(result))
    else:
        print(f"分类  {result['classification']}")
        print(f"访问  {result['src']} -> {result['tgt']}:{result['cls']} "
              f"{{ {' '.join(result['requested'])} }}")
        print(f"说明  {result['explanation']}")
        print(f"建议  {result['recommended']['title']}")
        _print_cross_layer(result.get("cross_layer"))
    return 0


def _print_cross_layer(view: Optional[dict]) -> None:
    """The application-layer part of the human answer, when there is one."""
    if not view:
        return
    if not view.get("app"):
        print(f"跨层  {view['headline']}")
        return
    print(f"跨层  {LAYER_LABEL.get(view['fix_layer'], view['fix_layer'])}")
    print(f"      {view['headline']}")
    for line in view.get("evidence", []):
        print(f"      · {line}")
    for line in view.get("advice", []):
        print(f"      → {line}")


if __name__ == "__main__":
    raise SystemExit(main())
