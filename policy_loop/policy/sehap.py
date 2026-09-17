"""``sehap_contexts`` -- the APL <-> SELinux domain bridge, indexed.

An OpenHarmony application does not choose its own SELinux domain. The platform
derives it from the *APL* (Ability Privilege Level) carried in the signing
profile, plus a ``debuggable`` flag, and ``sepolicy/**/sehap_contexts`` is where
that mapping is declared -- ``hap_restorecon`` reads those files on device.
Nothing in the ``.te`` tree states it::

    apl=system_core domain=system_core_hap type=system_core_hap_data_file
    apl=normal      domain=normal_hap      type=appdat
    apl=normal debuggable=true domain=debug_hap type=debug_hap_data_file

So an application developer whose app is denied sees ``scontext=u:r:normal_hap:s0``
-- a domain name that names neither their bundle nor the layer that owns the
fix. Indexing these files is what lets the engine connect the two.

Format: one entry per line, space-separated ``key=value`` fields, ``#`` comments.

* ``apl`` / ``domain`` -- always present; every line in both upstream trees has
  both. A line missing either is counted in :attr:`SehapTable.skipped` rather
  than guessed at.
* ``type`` -- the data-file type; optional (the webview entries carry none).
  Note that an entry carrying ``extension`` never contributes its ``type`` to
  anything: on device the extension form only sets ``extensionMap[ext].domain``,
  so the node's ``type`` comes from the base entry (``appdat`` for ``apl=normal``)
  and the ``type=`` written on those lines is dead weight.
* ``debuggable`` -- written only when true, so absence means false. Compared
  literally against ``"true"`` (``hap_restorecon.cpp:233``), which matters: a
  hypothetical ``debuggable=True`` is *false* on device, and reading it as true
  here would attribute a denial to ``debug_hap`` that never runs there.
* ``name`` / ``extension`` / ``extra`` -- the discriminators a subsystem uses to
  carve out a narrower entry: a bundle name (optionally ``bundle:sub``), a named
  extension, or a sandbox tag from the fixed set in :data:`KNOWN_EXTRAS`.

Line filtering mirrors ``CouldSkip`` (``hap_restorecon.cpp:117``): a line is
dropped when it is too short/long to be an entry, when its first non-space
character is ``#``, or when it does not contain ``apl=`` at all. One device
quirk is deliberately *not* mirrored: on device each token is classified by
substring search for ``domain=``/``type=``/... in a fixed priority order, so a
malformed token like ``xdomain=y`` would be read as a domain. Source files do
not contain such tokens, and emulating the tolerance would mean accepting
nonsense with device-specific meaning -- a worse failure than reporting it.


``domain -> apl`` is **not** a function, and the repeated domains are not
duplicates:

* ``distributed_isolate_hap`` is declared twice, once plain and once with
  ``debuggable=true`` -- that pair is the whole point of the entry.
* ``isolated_gpu`` is declared three times, with ``apl=normal``,
  ``system_basic`` and ``system_core`` -- one domain serving three levels.

So :meth:`SehapTable.lookup_domain` returns *every* entry for a domain and
:meth:`SehapTable.apls` returns the distinct levels. For the direction this
module exists for -- read a denial's ``scontext``, ask "is this an application
process, and at what level" -- a set is the honest answer, and collapsing it to
one level would invent a fact the platform does not have.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

__all__ = ["SEHAP_FILENAME", "KNOWN_EXTRAS", "SehapEntry", "SehapTable",
           "parse_sehap_text", "load_sehap"]

SEHAP_FILENAME = "sehap_contexts"

# hap_restorecon.cpp:84-85 -- the comment on the minimum is upstream's:
# sizeof("apl=x domain= type=").
CONTEXTS_LENGTH_MIN = 20
CONTEXTS_LENGTH_MAX = 1024

# hap_restorecon.cpp:74-80. An `extra=` value outside this set makes the whole
# line invalid on device (`isValid = false`, :264-267) -- so an unknown tag is
# dropped here too rather than carried as an opaque string.
KNOWN_EXTRAS = frozenset({
    "dlp_sandbox_read_only", "dlp_sandbox", "input_isolate",
    "input_isolate_full", "custom_sandbox", "isolated_gpu", "isolated_render",
})


@dataclass(frozen=True)
class SehapEntry:
    """One line of a ``sehap_contexts`` file."""

    apl: str
    domain: str
    type: str = ""
    debuggable: bool = False
    name: str = ""
    extension: str = ""
    extra: str = ""
    source: str = ""
    raw: str = ""

    def as_tuple(self) -> tuple:
        """The entry as a plain tuple -- used for set-equality assertions."""
        return (self.apl, self.domain, self.type, self.debuggable,
                self.name, self.extension, self.extra)


def parse_sehap_text(text: str, source: str = "<text>") -> Tuple[List[SehapEntry],
                                                                List[tuple]]:
    """Parse one ``sehap_contexts`` file into ``(entries, skipped)``.

    *skipped* holds ``(lineno, line, reason)`` for every line that did not
    become an entry -- reported rather than silently dropped, the same way
    ``PolicyIndex.skipped_count`` surfaces unexpanded statements. A dropped
    line here means a domain that the engine cannot attribute to an
    application, which is worth being able to see.
    """
    entries: List[SehapEntry] = []
    skipped: List[tuple] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        # Length bounds are checked on the raw line, as CouldSkip does.
        if len(line) <= CONTEXTS_LENGTH_MIN or len(line) > CONTEXTS_LENGTH_MAX:
            if line.strip() and not line.lstrip().startswith("#"):
                skipped.append((lineno, line, "length"))
            continue
        s = line.strip()
        if s.startswith("#"):
            continue
        if "apl=" not in line:
            skipped.append((lineno, line, "no apl="))
            continue
        fields: dict = {}
        malformed = False
        for token in s.split():
            key, sep, value = token.partition("=")
            if not sep or not key:
                malformed = True
                break
            fields[key] = value
        if malformed or "apl" not in fields:
            skipped.append((lineno, line, "malformed"))
            continue
        if "domain" not in fields:
            skipped.append((lineno, line, "no domain="))
            continue
        extra = fields.get("extra", "")
        if extra and extra not in KNOWN_EXTRAS:
            skipped.append((lineno, line, f"unknown extra={extra}"))
            continue
        entries.append(SehapEntry(
            apl=fields["apl"],
            domain=fields["domain"],
            type=fields.get("type", ""),
            # Literal "true" only (hap_restorecon.cpp:233).
            debuggable=fields.get("debuggable", "") == "true",
            name=fields.get("name", ""),
            extension=fields.get("extension", ""),
            extra=extra,
            source=source,
            raw=s,
        ))
    return entries, skipped


class SehapTable:
    """Every ``sehap_contexts`` entry found under a sepolicy tree."""

    def __init__(self) -> None:
        self.entries: List[SehapEntry] = []
        self.skipped: List[tuple] = []
        self._sources: List[str] = []
        self._by_domain: Optional[dict] = None
        self._by_name: Optional[dict] = None

    # ---- building ---------------------------------------------------------

    def add_text(self, text: str, source: str = "<text>") -> "SehapTable":
        entries, skipped = parse_sehap_text(text, source)
        self.entries.extend(entries)
        self.skipped.extend(skipped)
        self._sources.append(source)
        self._by_domain = None
        self._by_name = None
        return self

    # ---- indexes ----------------------------------------------------------

    @property
    def by_domain(self) -> dict:
        """``domain -> tuple(SehapEntry, ...)`` in file order."""
        if self._by_domain is None:
            grouped: dict = {}
            for e in self.entries:
                grouped.setdefault(e.domain, []).append(e)
            self._by_domain = {k: tuple(v) for k, v in grouped.items()}
        return self._by_domain

    @property
    def by_name(self) -> dict:
        """``name -> tuple(SehapEntry, ...)``; only the named entries.

        The reverse direction (bundle -> domain) is what the device uses to
        label a HAP; the engine uses it to say which bundle a denial belongs
        to once a bundle name is known.
        """
        if self._by_name is None:
            grouped: dict = {}
            for e in self.entries:
                if e.name:
                    grouped.setdefault(e.name, []).append(e)
            self._by_name = {k: tuple(v) for k, v in grouped.items()}
        return self._by_name

    # ---- queries ----------------------------------------------------------

    def lookup_domain(self, domain: str) -> Tuple[SehapEntry, ...]:
        """Every entry declaring *domain* (empty tuple when it is not a HAP
        domain at all -- which is itself the answer to "is this an app?")."""
        return self.by_domain.get(domain, ())

    def apls(self, domain: str) -> Tuple[str, ...]:
        """The distinct APL levels *domain* can run at, sorted."""
        return tuple(sorted({e.apl for e in self.lookup_domain(domain)}))

    def is_app_domain(self, domain: str) -> bool:
        return bool(domain) and domain in self.by_domain

    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted(self.by_domain))

    def apls_all(self) -> Tuple[str, ...]:
        return tuple(sorted({e.apl for e in self.entries}))

    # ---- reporting --------------------------------------------------------

    def summary(self) -> dict:
        """Counters for the PLI header / ``--index-info`` (host and device
        both recompute these, so a truncated file is caught on load)."""
        return {
            "hap_entries": len(self.entries),
            "hap_domains": len(self.by_domain),
            "hap_names": len(self.by_name),
            "hap_apls": len(self.apls_all()),
            "hap_debuggable": sum(1 for e in self.entries if e.debuggable),
            "hap_skipped": len(self.skipped),
        }

    def sources(self) -> Tuple[str, ...]:
        return tuple(self._sources)


def load_sehap(root) -> SehapTable:
    """Index every ``sehap_contexts`` file under *root* (OpenHarmony layout).

    Every one of them, not just ``base/public``: the per-subsystem files are
    where the isolated/sandboxed domains (``input_isolate_hap``,
    ``medialibrary_hap``, ``distributed_isolate_hap`` ...) are declared, and a
    reader that stops at the base file cannot classify exactly the domains a
    denial is most likely to name.
    """
    table = SehapTable()
    for path in sorted(Path(root).rglob(SEHAP_FILENAME)):
        table.add_text(path.read_text(encoding="utf-8", errors="replace"),
                       source=str(path))
    return table


def entries_as_tuples(entries: Iterable[SehapEntry]) -> set:
    return {e.as_tuple() for e in entries}
