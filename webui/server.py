"""PolicyLoop Web UI — stdlib-only HTTP server + agent API.

Usage:
    python -m webui.server [--port 8765] [--policy PATH] [--no-browser]

Default policy: the full upstream sepolicy if data/raw/oh-selinux exists
(otherwise the small fixture policy), cached in memory for fast repeat runs.

Endpoints:
    GET  /                  -> single-page UI (Agent Trace animation)
    GET  /api/meta          -> { scenarios, policy_label, policy_rules }
    POST /api/analyze       -> { denial } | { denial, policy }
                               returns the full SecurityCase (trace + results)
"""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from policy_loop.agents import Orchestrator
from policy_loop.agents.demo import SCENARIOS
from policy_loop.policy import load_dir, load_text

ROOT = Path(__file__).resolve().parent
INDEX_HTML = (ROOT / "static" / "index.html")
SMALL_POLICY = ROOT.parent / "data" / "fixtures" / "sample_policy.te"
FULL_POLICY = ROOT.parent / "data" / "raw" / "oh-selinux" / "sepolicy"


def default_policy_path() -> Path:
    return FULL_POLICY if FULL_POLICY.exists() else SMALL_POLICY


_cache: dict = {"path": None, "index": None, "label": ""}


def get_index(policy: str):
    if _cache["path"] == policy and _cache["index"] is not None:
        return _cache["index"]
    p = Path(policy)
    if p.is_dir():
        idx = load_dir(p)
        label = f"{p.name}（{len(idx.rules):,} 条规则）"
    else:
        idx = load_text(p.read_text(encoding="utf-8", errors="replace"),
                        source=str(p))
        label = f"{p.name}（{len(idx.rules)} 条规则）"
    _cache.update(path=policy, index=idx, label=label)
    return idx


def analyze_case(denial: str, policy: str | None = None) -> dict:
    policy = policy or default_policy_path()
    idx = get_index(policy)
    case = Orchestrator(index=idx).analyze(denial)
    return {
        "id": case.id,
        "policy_label": _cache["label"],
        "trace": [{"agent": t.agent, "action": t.action,
                   "status": t.status, "detail": t.detail}
                  for t in case.trace],
        "classification": case.classification,
        "explanation": case.explanation,
        "candidates": case.candidates,
        "recommended": case.recommended,
        "patch": case.patch,
        "patch_target_note": case.patch_target_note,
        "needs_human": case.needs_human,
        "review": case.review,
        "verify": case.verify,
    }


class Handler(BaseHTTPRequestHandler):
    # ------------------------------------------------------------------ #
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/meta":
            self._json(200, {
                "scenarios": [{"label": l, "denial": d} for l, d in SCENARIOS],
                "policy_label": _cache["label"],
                "policy_rules": len(_cache.get("index").rules)
                if _cache.get("index") else 0,
            })
            return
        if path in ("/", "/index.html"):
            body = INDEX_HTML.read_bytes() if INDEX_HTML.exists() else \
                b"<h1>index.html missing</h1>"
            self._send(200, body, "text/html; charset=utf-8")
            return
        self._json(404, {"error": f"not found: {path}"})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/api/analyze":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            denial = payload.get("denial", "")
            policy = payload.get("policy") or None
            if not denial:
                self._json(400, {"error": "missing 'denial'"})
                return
            result = analyze_case(denial, policy)
            self._json(200, {"ok": True, "case": result})
        except Exception as exc:  # noqa: BLE001 - report to the UI
            self._json(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, fmt, *args):  # quieter logs
        if "favicon" not in fmt:
            super().log_message(fmt, *args)


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="PolicyLoop Web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--policy", default=str(default_policy_path()))
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)

    print(f"indexing policy: {args.policy} ...")
    get_index(args.policy)   # pre-warm cache
    print(f"  -> {_cache['label']}")

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"PolicyLoop UI running at {url}   (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
