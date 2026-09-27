#!/usr/bin/env python3
"""Live view of a connected OpenHarmony device's screen -- and control of it --
in a browser tab.

There is no screen-mirroring service and no input-forwarding service on a stock
OpenHarmony image: what the device carries is ``snapshot_display`` and ``uitest
uiInput``, and nothing that speaks either over a socket. So this polls the
first and drives the second, then re-serves the frames as MJPEG, which every
browser renders natively as a video -- no plugins, no player, no dependencies
beyond the standard library.

Measured on a DAYU200 (RK3568, 720x1280 DSI): ~350 ms per frame, so ~3 fps. That
is deliberately stated rather than hidden. This is a proof-of-life panel for a
demo, not a mirror: what it is good at is showing that the device on the bench
reacts to what you do -- click in the page and the screen here moves.

    ./tools/boardscreen.py                 # -> http://127.0.0.1:8770/
    ./tools/boardscreen.py --fps 5 --port 9000
    ./tools/boardscreen.py --no-input      # watch only

Input is on by default because a page that shows a screen you cannot touch is
half a tool. It binds to 127.0.0.1 for that reason: everything here -- click,
drag, Back/Home, typed text -- is injected into a real device. Pass --bind
0.0.0.0 only if you mean to let the network drive it.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# hdc ships in the SDK's toolchains package, not on PATH by default.
HDC_FALLBACKS = [
    "hdc",
    "$HOME/ohos_sdk_dl/tc_extract/toolchains/hdc",
]

# Both the capture and the injection need a device-side round trip, and hdc's
# shell channel serialises them: overlapping them just queues. One lock keeps
# a click from landing while a frame is mid-capture and vice versa.
DEVICE_LOCK = threading.Lock()

PAGE = """<!doctype html>
<meta charset="utf-8">
<title>board screen</title>
<style>
  body { margin:0; background:#1b1b1f; color:#c9c9d1;
         font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;
         display:flex; flex-direction:column; align-items:center; gap:10px;
         padding:12px; }
  img  { max-height:calc(100vh - 118px); border-radius:10px;
         box-shadow:0 6px 28px #0008; background:#000;
         cursor:crosshair; touch-action:none; user-select:none; }
  .bar { display:flex; gap:8px; align-items:center; flex-wrap:wrap;
         justify-content:center; }
  button { background:#2c2c33; color:#d6d6de; border:1px solid #3d3d46;
           border-radius:7px; padding:5px 12px; font:inherit; cursor:pointer; }
  button:hover  { background:#3a3a44; }
  button:active { background:#4a4a56; }
  input[type=text] { background:#2c2c33; color:#d6d6de;
           border:1px solid #3d3d46; border-radius:7px; padding:5px 9px;
           font:inherit; width:190px; }
  .dot { width:7px; height:7px; border-radius:50%; background:#39d353;
         display:inline-block; margin-right:6px; }
  .dead .dot { background:#d3394a; }
  .hint { color:#7a7a86; }
</style>
<div class="bar">
  <span id="s"><span class="dot"></span>connecting</span>
  <span class="hint" id="sz"></span>
</div>
<img id="v" src="/stream.mjpeg">
<div class="bar">
  <button data-k="Back">&#9664; Back</button>
  <button data-k="Home">&#9673; Home</button>
  <button data-k="Power">&#9211; Power</button>
  <input type="text" id="t" placeholder="type text, Enter to send">
</div>
<script>
const v = document.getElementById('v'), s = document.getElementById('s'),
      t = document.getElementById('t'), sz = document.getElementById('sz');
let W = 0, H = 0, last = null, down = null;

fetch('/api/info').then(r => r.json()).then(d => {
  W = d.width; H = d.height;
  sz.textContent = W + 'x' + H + (d.input ? '' : '  [read-only]');
  if (!d.input) { document.querySelectorAll('button,input').forEach(
      e => e.disabled = true); t.placeholder = 'input disabled'; }
});

v.onerror = () => { s.parentElement.classList.add('dead');
                    s.innerHTML = '<span class="dot"></span>lost -- reload'; };

function post(body) {
  return fetch('/input', {method:'POST', body: JSON.stringify(body)})
    .then(r => r.json()).catch(() => ({ok:false}));
}
function at(e) {                       // page coords -> device coords
  const r = v.getBoundingClientRect();
  return { x: Math.round((e.clientX - r.left) / r.width  * W),
           y: Math.round((e.clientY - r.top ) / r.height * H) };
}

v.addEventListener('pointerdown', e => { down = at(e); v.setPointerCapture(e.pointerId); });
v.addEventListener('pointerup', e => {
  if (!down) return;
  const up = at(e);
  const far = Math.hypot(up.x - down.x, up.y - down.y) > 12;
  // A drag has to become a swipe or scrolling is impossible; a tap is a click.
  // uitest's velocity is px/s and wants 200..40000.
  if (far) post({action:'swipe', x1:down.x, y1:down.y, x2:up.x, y2:up.y});
  else     { post({action:'click', x:up.x, y:up.y}); last = up; }
  down = null;
});

document.querySelectorAll('button[data-k]').forEach(b =>
  b.onclick = () => post({action:'key', key:b.dataset.k}));

t.addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  // inputText types into whatever on the device already has focus, so the
  // position only matters when the field was never tapped in the page first.
  post({action:'text', text:t.value, x:last ? last.x : Math.round(W/2),
        y:last ? last.y : Math.round(H/2)});
  t.value = '';
});
</script>
"""


def find_hdc(explicit: str | None) -> str:
    for cand in ([explicit] if explicit else []) + HDC_FALLBACKS:
        if not cand:
            continue
        cand = os.path.expandvars(os.path.expanduser(cand))
        path = shutil.which(cand) if os.sep not in cand else cand
        if path and os.path.exists(path):
            return path
    sys.exit("boardscreen: hdc not found; pass --hdc /path/to/hdc")


class Device:
    """One device: frame capture, input injection, and the display geometry."""

    def __init__(self, hdc: str, display: int, allow_input: bool):
        self.hdc, self.display = hdc, display
        self.allow_input = allow_input
        self.width, self.height = 0, 0
        self.scratch = "/data/local/tmp/.bs.jpeg"

    def shell(self, cmd: str, timeout: float = 20) -> subprocess.CompletedProcess:
        with DEVICE_LOCK:
            return subprocess.run([self.hdc, "shell", cmd],
                                  capture_output=True, text=True, timeout=timeout)

    def probe(self) -> None:
        """Learn the display size; snapshot_display prints it on every run."""
        p = self.shell(f"snapshot_display -i {self.display} -f {self.scratch}")
        m = re.search(r"width (\d+), height (\d+)", p.stdout + p.stderr)
        if m:
            self.width, self.height = int(m.group(1)), int(m.group(2))
        elif not self.width:
            raise SystemExit("boardscreen: could not read display size "
                             "-- is snapshot_display present?")

    def grab(self) -> bytes | None:
        # Two round trips, which measured faster than `cat` through the shell's
        # stdout (347 ms vs 412 ms per frame) -- the file channel is optimised
        # for this and the shell path is not.
        #
        # Note `hdc file recv <remote> -` does *not* mean stdout: it writes a
        # progress line and exits 0, so the destination has to be a real file.
        self.shell(f"snapshot_display -i {self.display} -f {self.scratch}")
        with tempfile.TemporaryDirectory() as td:
            local = pathlib.Path(td) / "f.jpeg"
            with DEVICE_LOCK:
                subprocess.run([self.hdc, "file", "recv", self.scratch,
                                str(local)], capture_output=True, timeout=20)
            data = local.read_bytes() if local.exists() else b""
        return data if data.startswith(b"\xff\xd8") else None

    def inject(self, req: dict) -> dict:
        if not self.allow_input:
            return {"ok": False, "error": "input disabled (--no-input)"}
        a = req.get("action")
        if a == "click":
            cmd = f"uitest uiInput click {int(req['x'])} {int(req['y'])}"
        elif a == "swipe":
            x1, y1 = int(req["x1"]), int(req["y1"])
            x2, y2 = int(req["x2"]), int(req["y2"])
            dist = max(1, int((abs(x2 - x1) ** 2 + abs(y2 - y1) ** 2) ** 0.5))
            vel = min(40000, max(200, dist * 6))
            cmd = f"uitest uiInput swipe {x1} {y1} {x2} {y2} {vel}"
        elif a == "key":
            key = str(req["key"])
            if key not in ("Back", "Home", "Power"):
                return {"ok": False, "error": f"refusing key {key!r}"}
            cmd = f"uitest uiInput keyEvent {key}"
        elif a == "text":
            # shlex.quote is exactly the POSIX single-quote escaping the
            # device's /bin/sh needs; anything else here is an injection into a
            # root shell on the device.
            cmd = (f"uitest uiInput inputText {int(req['x'])} {int(req['y'])} "
                   f"{shlex.quote(str(req.get('text', '')))}")
        else:
            return {"ok": False, "error": f"unknown action {a!r}"}
        p = self.shell(cmd)
        out = (p.stdout + p.stderr).strip()
        # uitest answers "No Error" on success and something else on failure.
        ok = "No Error" in out or out == ""
        return {"ok": ok, "out": out[:200]}


class Frames:
    """Latest frame plus a counter, filled by a polling thread.

    Deliberately a single slot rather than a queue: if the consumer is slower
    than the poller, only the newest frame is worth showing, and a queue would
    just add latency that grows without bound.
    """

    def __init__(self, dev: Device, fps: float):
        self.dev = dev
        self.period = 1.0 / fps if fps > 0 else 0.35
        self.lock = threading.Lock()
        self.jpeg: bytes | None = None
        self.n = 0
        self.error: str | None = None
        self.cond = threading.Condition(self.lock)
        self.stop = threading.Event()

    def poll(self):
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                data = self.dev.grab()
                with self.cond:
                    if data:
                        self.jpeg, self.error = data, None
                        self.n += 1
                    else:
                        self.error = "empty frame"
                    self.cond.notify_all()
            except Exception as exc:  # noqa: BLE001 - surfaced in the page
                with self.cond:
                    self.error = f"{type(exc).__name__}: {exc}"
                    self.cond.notify_all()
            self.stop.wait(max(0.0, self.period - (time.monotonic() - t0)))

    def wait_for(self, seen: int, timeout: float = 10.0) -> tuple[bytes | None, int]:
        with self.cond:
            if self.n == seen:
                self.cond.wait(timeout)
            return self.jpeg, self.n


class Handler(BaseHTTPRequestHandler):
    dev: Device
    frames: Frames

    def log_message(self, *a):  # keep the console quiet during a demo
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/info":
            self._json({"width": self.dev.width, "height": self.dev.height,
                        "input": self.dev.allow_input})
        elif path == "/frame.jpeg":
            jpeg, _ = self.frames.wait_for(self.frames.n, timeout=5)
            if not jpeg:
                self.send_error(503, self.frames.error or "no frame")
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(jpeg)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(jpeg)
        elif path == "/stream.mjpeg":
            self.send_response(200)
            self.send_header("Content-Type",
                             "multipart/x-mixed-replace; boundary=frame")
            self.end_headers()
            seen = 0
            try:
                while True:
                    jpeg, seen = self.frames.wait_for(seen, timeout=15)
                    if not jpeg:
                        break
                    self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\n"
                                     b"Content-Length: "
                                     + str(len(jpeg)).encode() + b"\r\n\r\n")
                    self.wfile.write(jpeg)
                    self.wfile.write(b"\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass  # the tab was closed or reloaded
        else:
            self.send_error(404)

    def do_POST(self):  # noqa: N802
        if self.path.split("?")[0] != "/input":
            self.send_error(404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
            result = self.dev.inject(req)
        except Exception as exc:  # noqa: BLE001 - reported to the page
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        self._json(result, 200 if result.get("ok") else 400)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--fps", type=float, default=3.0,
                    help="poll rate; ~3 is the measured ceiling (default 3)")
    ap.add_argument("--display", type=int, default=0)
    ap.add_argument("--hdc", default=None)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--no-input", action="store_true",
                    help="watch only; do not inject clicks or keys")
    args = ap.parse_args(argv)

    hdc = find_hdc(args.hdc)
    targets = subprocess.run([hdc, "list", "targets"],
                             capture_output=True, text=True).stdout.strip()
    if not targets or "Empty" in targets:
        sys.exit("boardscreen: no device -- check `hdc list targets`")

    dev = Device(hdc, args.display, allow_input=not args.no_input)
    dev.probe()
    print(f"boardscreen: device {targets.splitlines()[0]}", flush=True)
    print(f"boardscreen: display {dev.width}x{dev.height}  "
          f"input {'on' if dev.allow_input else 'off'}", flush=True)

    frames = Frames(dev, args.fps)
    Handler.dev, Handler.frames = dev, frames
    threading.Thread(target=frames.poll, daemon=True).start()

    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    srv.daemon_threads = True
    print(f"boardscreen: http://{args.bind}:{args.port}/  (Ctrl-C to stop)",
          flush=True)
    if args.bind not in ("127.0.0.1", "localhost"):
        print(f"boardscreen: WARNING -- bound to {args.bind}; anyone who can "
              f"reach this port can drive the device", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nboardscreen: stopped")
    finally:
        frames.stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
