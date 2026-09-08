"""OpenHarmony-style AVC denial parser.

Deterministic, dependency-free parser for `avc: denied` audit lines as emitted by
the OpenHarmony security (SELinux) subsystem. It understands both standard SELinux
fields and OpenHarmony-specific log shapes:

* object classes       : file, dir, chr_file, binder, fd, sock_file, ...
* OH-specific classes  : ``parameter_service`` (``parameter=...``),
                         ``samgr_class`` (``service=...``), ``hdf_devmgr_class``
* ioctl detail         : ``ioctlcmd=0x...`` (feeds allowxperm decisions)
* mode flag            : ``permissive=0|1``

No LLM is used here; parsing correctness is a hard acceptance metric.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Iterator, Optional

__all__ = ["DenialRecord", "parse", "parse_event"]

# --------------------------------------------------------------------------- #
# Regexes
# --------------------------------------------------------------------------- #

# Match the start of each denial event. Logs often carry prefixes such as
# "audit: type=1400 audit(...):", "avc_audit_slow:260]", "[hmseh:392]", "# " ...
_AVC_START_RE = re.compile(r"\bavc\s*:\s*denied", re.IGNORECASE)

# Capture the permission set:  denied { read write }   /   denied { ioctl }
_DENIED_PERMS_RE = re.compile(
    r"\bdenied\s*\{\s*(?P<perms>[^}]*?)\s*\}", re.IGNORECASE
)

# key=value tokens. Values may be double-quoted (may contain spaces) or bare.
_KV_RE = re.compile(
    r"(?P<key>"
    r"pid|comm|path|name|dev|ino|ioctlcmd|scontext|tcontext|tclass|permissive"
    r"|parameter|service|sid|uid|gid"
    r")\s*=\s*"
    r"(?P<value>\"(?:[^\"\\]|\\.)*\"|[^\s,]+)"
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class DenialRecord:
    """A single structured denial (Security Case input)."""

    raw: str
    source_domain: Optional[str]          # scontext type, e.g. "media_service"
    target_type: Optional[str]            # tcontext type, e.g. "dev_camera_file"
    tclass: Optional[str]                 # e.g. "chr_file", "parameter_service"
    permissions: tuple                     # e.g. ("read", "ioctl")
    permissive: Optional[bool]            # True=logged only, False=blocked
    # --- provenance / enrichment ------------------------------------------
    comm: Optional[str] = None            # process comm (may include path)
    pid: Optional[int] = None
    path: Optional[str] = None            # file path if present
    name: Optional[str] = None
    ioctl_cmd: Optional[str] = None       # e.g. "0x7003" (for allowxperm checks)
    parameter: Optional[str] = None       # OH parameter_service target
    service: Optional[str] = None         # OH samgr_class / hdf service id

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _split_context(ctx: str) -> tuple:
    """Split 'u:r:media_service:s0' -> (user, role, type, mls)."""
    parts = ctx.split(":")
    user = parts[0] if parts else ""
    role = parts[1] if len(parts) > 1 else ""
    type_ = parts[2] if len(parts) > 2 else ""
    mls = ":".join(parts[3:]) if len(parts) > 3 else None
    return user, role, type_, mls


def _parse_event(text: str) -> DenialRecord:
    """Parse one denial event block into a DenialRecord."""
    m = _DENIED_PERMS_RE.search(text)
    perms = tuple(m.group("perms").split()) if m else ()

    kv: dict = {}
    for km in _KV_RE.finditer(text):
        kv.setdefault(km.group("key"), _strip_quotes(km.group("value")))

    sctx, tctx = kv.get("scontext"), kv.get("tcontext")
    source_domain = _split_context(sctx)[2] if sctx else None
    target_type = _split_context(tctx)[2] if tctx else None

    permissive_raw = kv.get("permissive")
    permissive = (
        permissive_raw == "1" if permissive_raw in ("0", "1") else None
    )

    pid = kv.get("pid")
    try:
        pid_int = int(pid) if pid and pid.isdigit() else None
    except ValueError:
        pid_int = None

    return DenialRecord(
        raw=text.strip(),
        source_domain=source_domain,
        target_type=target_type,
        tclass=kv.get("tclass"),
        permissions=perms,
        permissive=permissive,
        comm=kv.get("comm"),
        pid=pid_int,
        path=kv.get("path"),
        name=kv.get("name"),
        ioctl_cmd=kv.get("ioctlcmd"),
        parameter=kv.get("parameter"),
        service=kv.get("service"),
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def parse(text: str) -> list:
    """Parse a chunk of log text into a list of DenialRecord.

    Each ``avc: denied`` occurrence starts a new record; the remainder of that
    block (possibly split across lines) belongs to the same event.
    """
    text = text.replace("\\\n", " ")  # join continuation lines
    # Each 'avc: denied' opens a new record. Boundaries are snapped to the
    # start of the line that contains the marker, so prefixes on the same line
    # (e.g. "audit: type=1400 audit(...):") stay with their own event.
    matches = list(_AVC_START_RE.finditer(text))
    if not matches:
        return []
    bounds = [text.rfind("\n", 0, mm.start()) + 1 for mm in matches]
    if bounds[-1] != len(text):
        bounds.append(len(text))
    records = []
    for i in range(len(bounds) - 1):
        block = text[bounds[i]: bounds[i + 1]]
        # keep log lines of this event; drop interleaved '#' comments, EXCEPT
        # lines that themselves carry an 'avc: denied' marker (e.g. upstream
        # .te files keep real denials as '#' comments that we want to parse).
        lines = [
            ln for ln in block.splitlines()
            if ln.strip()
            and (not ln.lstrip().startswith("#") or _AVC_START_RE.search(ln))
        ]
        if lines:
            records.append(_parse_event("\n".join(lines)))
    return records


def parse_event(text: str) -> DenialRecord:
    """Parse exactly one denial event (first match wins)."""
    starts = [mm.start() for mm in _AVC_START_RE.finditer(text)]
    if not starts:
        raise ValueError("no 'avc: denied' event found in input")
    block = text[starts[0]:]
    return _parse_event(block)


# --------------------------------------------------------------------------- #
# Simple CLI so the parser is demoable without any framework
# --------------------------------------------------------------------------- #

def _cli(argv: Optional[list] = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Parse OpenHarmony AVC denials")
    ap.add_argument("--text", help="single denial text")
    ap.add_argument("--file", help="path to a log file")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        records = parse(text)
    elif args.text:
        records = parse(args.text)
    else:
        ap.error("provide --text or --file")

    for r in records:
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2)
              if args.json else r)
    return 0 if records else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
