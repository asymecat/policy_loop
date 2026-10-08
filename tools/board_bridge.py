"""Board bridge -- the PC half of the on-device PolicyLoop console.

The board-side HAP (`pl_console`) shows one switch and one list. It cannot do
the analysis itself and it is not a shortcut: `normal_hap` is denied both
`/dev/kmsg` and netlink sockets, so an application on the board cannot read the
audit stream at all. The switch therefore *asks* this process to work, and this
process answers with what the engine found.

Transport is `hdc rport tcp:8787 tcp:8787` over USB -- the board's `eth0` is up
with zero traffic, so a LAN route does not exist to use.

Endpoints:
    GET /state           -> {running, index, findings[], error}
    GET /toggle?on=0|1   -> {ok, running}

Each finding is one *distinct* denial (deduplicated on the access, not the log
line), classified by the same engine the rest of PolicyLoop uses.

Usage:
    python -m tools.board_bridge [--port 8787] [--policy DIR] [--interval 3]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from policy_loop.explain import explain
from policy_loop.policy import load

DEFAULT_POLICY = (Path.home() / "board-5.0.3-fingerprint"
                  / "selinux_adapter-5.0.3-0878c56e3" / "sepolicy")
# Same convention as tools/boardscreen.py: PL_HDC wins, then a $HOME-relative
# fallback, so a fresh clone works without a hard-coded /home/<user>.
DEFAULT_HDC = os.environ.get("PL_HDC") or str(
    Path.home() / "ohos_sdk_dl" / "tc_extract" / "toolchains" / "hdc")

# Domains whose denials are caused by *our own* tooling -- screen capture, the
# root shell hdc lands in, the UI driver. They are real denials but they are not
# board defects, and the console labels them separately so a demo never counts
# them as findings against the firmware.
TOOL_DOMAINS = {"snapshot_display", "su", "uitest", "shell", "sh", "dmesg",
                "toybox", "hdcd", "hdcd_shell",
                # PolicyLoop's own collector, same reasoning one step closer to
                # home: its probe (--debug-log) and the /proc and /dev/console
                # it reads at startup are our footprint, not defects in the
                # firmware under test. Without this the probe line is counted
                # against the board.
                "pl_collector"}

_AVC = re.compile(r"avc:\s+denied\s+\{([^}]*)\}")
_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _domain(scontext: str) -> str:
    """`u:r:render_service:s0` -> `render_service`."""
    parts = scontext.split(":")
    return parts[2] if len(parts) > 2 else scontext


def _type(tcontext: str) -> str:
    """`u:object_r:dev_mali:s0` -> `dev_mali`."""
    parts = tcontext.split(":")
    return parts[2] if len(parts) > 2 else tcontext


def parse_avc(line: str):
    """One kernel audit line -> the access it describes, or None.

    The dedup key is the *access* (source, target, class, perms, ioctl command),
    never the raw text: the log repeats the same denial with a new pid and
    timestamp every time the kernel retries, and `render_service -> dev_mali`
    is one finding whether it fired 3 times or 300.
    """
    m = _AVC.search(line)
    if not m:
        return None
    perms = tuple(sorted(m.group(1).split()))
    f = {k: v.strip('"') for k, v in _FIELD.findall(line)}
    sctx, tctx = f.get("scontext", ""), f.get("tcontext", "")
    if not sctx or not tctx:
        return None
    ioctl = f.get("ioctlcmd", "")
    return {
        "key": (sctx, tctx, f.get("tclass", ""), perms, ioctl),
        "line": line,
        "src": _domain(sctx),
        "tgt": _type(tctx),
        "cls": f.get("tclass", ""),
        "perms": perms,
        "ioctl": ioctl,
        "origin": "tool" if _domain(sctx) in TOOL_DOMAINS else "board",
    }


class Watcher:
    """Polls the board and keeps the latest classified snapshot."""

    def __init__(self, hdc: str, index, interval: float, limit: int,
                 label: str) -> None:
        self.hdc = hdc
        self.index = index
        self.interval = interval
        self.limit = limit
        self.label = label
        self.running = False
        self.error = ""
        self.findings: list = []
        self._cache: dict = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    def _read_board(self) -> list:
        """Every `avc: denied` line currently in the board's kernel ring."""
        out = subprocess.run(
            [self.hdc, "shell", "dmesg 2>/dev/null | grep 'avc:'"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        return [ln for ln in out.replace("\r", "").splitlines() if "avc:" in ln]

    def _snapshot(self) -> None:
        seen: dict = {}
        for line in self._read_board():
            rec = parse_avc(line)
            if rec is None:
                continue
            slot = seen.setdefault(rec["key"], dict(rec, count=0))
            slot["count"] += 1

        # Board defects first -- those are the ones a demo is about.
        ordered = sorted(seen.values(),
                         key=lambda r: (r["origin"] == "tool", -r["count"]))

        findings = []
        for rec in ordered[: self.limit]:
            if rec["key"] not in self._cache:
                try:
                    res = explain(rec["line"], index=self.index)
                except Exception as exc:  # noqa: BLE001 - surfaced on screen
                    res = None
                    self.error = f"{type(exc).__name__}: {exc}"
                self._cache[rec["key"]] = res
            res = self._cache[rec["key"]]
            if res is None:
                continue
            op = f"ioctl {res['ioctl']}" if res.get("ioctl") else \
                " ".join(res.get("requested") or rec["perms"])
            verdict = f"{res.get('review') or '?'} · {res.get('verify') or '?'}"
            if res.get("needs_human"):
                verdict = "需人工介入"
            findings.append({
                "origin": rec["origin"],
                "src": res["src"],
                "tgt": f"{res['tgt']}:{res['cls']}",
                "op": f"{op}   ×{rec['count']}",
                "cls": res["classification"],
                "fix": res.get("patch") or "",
                "verdict": verdict,
            })
        with self._lock:
            self.findings = findings

    def _loop(self) -> None:
        while self.running:
            try:
                self._snapshot()
                with self._lock:
                    self.error = ""
            except Exception as exc:  # noqa: BLE001 - surfaced on screen
                with self._lock:
                    self.error = f"读板子失败：{type(exc).__name__}: {exc}"
            for _ in range(int(self.interval * 10)):
                if not self.running:
                    return
                time.sleep(0.1)

    # ------------------------------------------------------------------ #
    def toggle(self, on: bool) -> None:
        with self._lock:
            if on == self.running:
                return
            self.running = on
            if not on:
                self._thread = None
                return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def state(self) -> dict:
        with self._lock:
            return {"running": self.running, "index": self.label,
                    "findings": list(self.findings), "error": self.error}


def make_handler(watcher: Watcher):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, obj) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            path, _, query = self.path.partition("?")
            if path == "/state":
                self._json(200, watcher.state())
                return
            if path == "/toggle":
                on = "on=1" in query
                watcher.toggle(on)
                self._json(200, {"ok": True, **watcher.state()})
                return
            self._json(404, {"error": f"not found: {path}"})

        def log_message(self, fmt, *args):
            pass

    return Handler


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--policy", default=str(DEFAULT_POLICY))
    ap.add_argument("--hdc", default=DEFAULT_HDC)
    ap.add_argument("--interval", type=float, default=3.0,
                    help="seconds between board polls while running")
    ap.add_argument("--limit", type=int, default=12,
                    help="max distinct findings to classify per poll")
    args = ap.parse_args(argv)

    print(f"indexing {args.policy} ...", flush=True)
    index = load(args.policy)
    # The console shows this line, and which tree the index came from is the
    # single most important thing on it: the same denial gets a confident wrong
    # answer from the master index that the 5.0.3 index answers correctly.
    m = re.search(r"-(\d+\.\d+\.\d+)-([0-9a-f]{7,})", args.policy)
    label = f"{m.group(1)} @ {m.group(2)[:8]}" if m else args.policy
    print(f"  -> {len(index.rules):,} rules", flush=True)

    watcher = Watcher(args.hdc, index, args.interval, args.limit, label)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(watcher))
    print(f"board bridge on http://{args.host}:{args.port}   (Ctrl+C to stop)\n"
          f"  pair it with:  hdc rport tcp:{args.port} tcp:{args.port}",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
