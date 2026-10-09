"""Cross-layer view: read an ``avc: denied`` line back in application terms.

The bridge this module walks is declared in ``sehap_contexts`` (see
``sehap.py``): an application's SELinux domain is derived from the *APL* in its
signing profile. Both ends of that bridge already exist in the engine -- the
domain names the system layer, the APL names the application layer -- and this
module is the one place that puts a denial in front of both, because the two
layers own different fixes:

    scontext=u:r:normal_hap  ->  APL=normal  ->  every *normal* app shares it

**The fact that makes the answer non-obvious**: ``*_hap`` domains are *shared*.
``normal_hap`` is not "the app that got denied", it is every normal-APL app on
the device. So ``allow normal_hap sys_file:file read`` is not a narrow fix for
one app; it is a platform-wide grant. Whether that is the right move depends on
something the ``.te`` tree alone cannot say -- and that is what this module
computes:

*If some other app domain already has the access and this one does not*, the
platform has drawn a line between them. For the two ``normal_hap ->
sys_file:file`` cases in the real corpus that line is the APL boundary itself
(``sys_file`` is readable by ``system_basic``/``system_core`` apps, never by
``normal`` ones). Patching the ``.te`` would erase a deliberate privilege
boundary; the honest answer is to send the developer to the application layer
(higher APL, or go through a system service) instead.

*If no app domain has it*, nothing is being defended by the gap: it is a
missing rule, and the system layer owns the fix -- with the caveat that the
rule lands on a shared domain, so its blast radius is every app at that level.

What this module deliberately does **not** do:

* It does not *decide*. It returns a view (headline + evidence + the queries
  it ran), and the caller decides how loudly to say it. In particular it must
  not silently re-bucket a case in ``converge``: the buckets are byte-compared
  against the on-device ``Converge()`` (see ``tests/diff_device.py``), so a
  cross-layer verdict that changed a category would turn the project's main
  safety net red. The device now *can* build this view -- the ``@hap`` table
  rides in the PLI and ``--explain --cross-layer`` reproduces it field for
  field -- but ``Converge()`` does not emit it and does not consult it, so the
  batch buckets stay identical on both sides. Upgrading this from advisory to a
  seventh guard would change that and is tracked as a separate change.
* It does not guess a bundle name. A denial carries ``scontext``, not a bundle,
  and ``sehap_contexts`` also maps *names* to domains -- so the direction
  "domain -> bundle" is one-to-many and unknowable from a log line. Only the
  name/extension/extra declarations of the domain are reported, as the
  narrowing the platform applied, not as an identification of the app.

Deterministic, stdlib-only. Never writes policy.
"""

from __future__ import annotations

from typing import Optional, Tuple

from policy_loop.export.pli import _hap_sort_key

__all__ = ["APL_ORDER", "LAYER_LABEL", "apl_rank", "analyze",
           "app_domain_clusters"]

# How the two layers are named in front of a human. Lives here, next to the
# `fix_layer` values it labels, so the CLI, the agent trace and the markdown
# report cannot drift into three spellings of the same answer.
LAYER_LABEL = {
    "app": "应用层（module.json / 签名 APL）",
    "system": "系统层（.te 策略）",
    "none": "无需修复（策略已允许）",
}

# The platform's privilege ladder. ``normal`` < ``system_basic`` < ``system_core``
# (docs: "APL 等级"), and the ordering is what turns "some other domain allows
# it" into "a *higher* level allows it" -- the difference between a boundary
# and an accident.
APL_ORDER = {"normal": 0, "system_basic": 1, "system_core": 2}

_UNKNOWN_APL = -1


def apl_rank(apl: str) -> int:
    """Rank of *apl*; unknown levels sort below every known one.

    An unknown level is not guessed at: it makes the boundary claim
    unattributable, and the caller says so instead of asserting a direction.
    """
    return APL_ORDER.get(apl, _UNKNOWN_APL)


def _as_dict(entry) -> dict:
    """One `sehap_contexts` entry as the view reports it.

    `entry.source` -- the file the entry was read from -- is deliberately not
    here. It is a build-machine path, the PLI does not carry it (see
    ``export/pli.py``: seven fields, and the device has no sepolicy source to
    read one from), and nothing reads it. Carrying it would have made this view
    the one part of the engine the on-device tool could not reproduce, which is
    exactly what ``tests/diff_device.py`` exists to catch.
    """
    return {"apl": entry.apl, "domain": entry.domain, "type": entry.type,
            "debuggable": entry.debuggable, "name": entry.name,
            "extension": entry.extension, "extra": entry.extra}


def _declared_in(index, domain: str) -> bool:
    """Is *domain* a type (or attribute) this policy corpus declares?

    Mirrors the device's ``IsDeclaredTypeOrAttr`` (``typeNames_ u attrNames_``),
    the same union ``resolve_logical_target`` uses to refuse a candidate it
    cannot see. A ``sehap_contexts`` entry for a domain this corpus never
    declares cannot be queried -- reporting it as "denied" would dress up "not
    in this index" as a policy answer.
    """
    return domain in index.type_attrs or domain in index.attributes


def _debug_pair(index, domain: str, own_entries) -> dict:
    """The debug/release counterpart of *domain*, if the platform declares one.

    ``apl=normal domain=normal_hap`` and ``apl=normal debuggable=true
    domain=debug_hap`` are the same application under two builds -- the pair
    behind "调试能跑、打包就挂". Two shapes exist in the real tree:

    * two *domains* differing only in the flag (``normal_hap`` / ``debug_hap``,
      ``input_isolate_hap`` / ``input_isolate_debug_hap``);
    * one domain declared twice (``distributed_isolate_hap``), where the flag
      selects the data-file type rather than the domain.

    A candidate must match on everything else -- same APL level set, same
    ``extra``, ``name`` and ``extension`` -- or ``input_isolate_debug_hap``
    would be offered as the debug build of ``normal_hap``. That is a wrong
    answer of exactly the kind this module exists to avoid.
    """
    flags = {e.debuggable for e in own_entries}
    if len(flags) > 1:
        return {"kind": "same_domain", "domain": domain, "allows": None}
    own_flag = flags.pop()
    levels = {e.apl for e in own_entries}
    extra = {e.extra for e in own_entries}
    names = {e.name for e in own_entries}
    exts = {e.extension for e in own_entries}
    for other in index.sehap.domains():
        if other == domain:
            continue
        entries = index.sehap.lookup_domain(other)
        other_flags = {e.debuggable for e in entries}
        if len(other_flags) != 1 or other_flags == {own_flag}:
            continue
        if ({e.apl for e in entries} == levels
                and {e.extra for e in entries} == extra
                and {e.name for e in entries} == names
                and {e.extension for e in entries} == exts):
            return {"kind": "sibling", "domain": other, "allows": None}
    return {"kind": "none", "domain": "", "allows": None}


def app_domain_clusters(index, records) -> Tuple[int, int]:
    """``(clusters whose scontext is an app domain, clusters total)``.

    The size of the cross-layer surface, for the report header: it is worth
    stating that most denials are *not* cross-layer at all, so a reader does
    not take the APL section as the general case.
    """
    sehap = getattr(index, "sehap", None)
    total = len(records)
    if sehap is None:
        return 0, total
    return (sum(1 for r in records
                if sehap.is_app_domain(getattr(r, "source_domain", "") or "")),
            total)


def analyze(index, src: str, tgt: str, cls: str, perms,
            allowed: Optional[bool] = None, service: str = "") -> Optional[dict]:
    """The cross-layer view of one access, or None when there is no bridge.

    *allowed* is the caller's verdict for ``src -> tgt`` (converge already has
    it and must not pay for it twice); None means "not asked", and it is then
    queried here.

    *service* is the denial's ``service=`` field, needed only to undo an M3
    placeholder: every query below has to run against the *same* target the
    caller queried, or "this domain is denied" and "this domain is allowed"
    would be statements about two different accesses. The resolution is
    ``PolicyIndex.resolve_logical_target`` -- the one implementation, not a
    copy -- and it is applied to the queries only; the raw target stays in the
    view that the advice prints, matching what the log actually carried.
    """
    sehap = getattr(index, "sehap", None)
    if sehap is None or not sehap.entries:
        return None

    perms = tuple(sorted(set(perms or ())))
    resolved_tgt = ""
    if service:
        resolved_tgt = index.resolve_logical_target(src, cls, tgt, service,
                                                    frozenset(perms)) or ""
    qtgt = resolved_tgt or tgt
    src_entries = sehap.lookup_domain(src)
    if not src_entries:
        return {"app": False, "domain": src, "apl": [], "fix_layer": "system",
                "headline": (f"scontext「{src}」不是应用域（未在 sehap_contexts "
                             f"中声明），跨层不适用：按系统层处理。"),
                "advice": [], "evidence": [], "variants": [],
                "boundary": None, "debug_pair": None}

    if allowed is None:
        allowed = index.has_access(src, qtgt, cls, perms)[0]

    levels = sorted({e.apl for e in src_entries})
    multi_level = len(levels) > 1
    dbg = any(e.debuggable for e in src_entries)

    # --- who else could do it? ---------------------------------------------
    allowing: dict = {}
    uncovered: list = []
    itself_allows_multiple = False
    for other in sehap.domains():
        if other == src:
            continue
        if not _declared_in(index, other):
            uncovered.append(other)
            continue
        ok, _, _ = index.has_access(other, qtgt, cls, perms)
        if ok:
            allowing[other] = sorted({e.apl for e in sehap.lookup_domain(other)})

    own_rank = max((apl_rank(a) for a in levels), default=_UNKNOWN_APL)
    # Sorted by ladder position, not alphabetically: the ranking is the claim
    # ("a *higher* level has it"), so the list has to read in that order.
    higher = sorted({lvl for lvls in allowing.values() for lvl in lvls
                     if apl_rank(lvl) > own_rank}, key=apl_rank)
    # An APL outside the known ladder makes "higher" meaningless -- every
    # ranked level would look higher than -1. Refuse the claim rather than
    # invent a direction for a level this engine has never been taught.
    unknown_apl = own_rank == _UNKNOWN_APL
    boundary = (not multi_level) and not unknown_apl and bool(higher)

    pair = _debug_pair(index, src, src_entries)
    if pair["kind"] == "sibling":
        pair["allows"] = index.has_access(pair["domain"], qtgt, cls, perms)[0]

    # Sorted, not in file order: the PLI writes its `@hap` lines with the same
    # key (export/pli.py:_hap_sort_key), so this is the order the on-device tool
    # can reproduce. File order is a fact about the host's sepolicy tree -- which
    # files it walked first -- and the device has no tree to walk.
    variants = [_as_dict(e) for e in sorted(src_entries, key=_hap_sort_key)]
    scope = (f"共享域（APL={levels[0]} 的全部应用共用）"
             if not multi_level else
             f"共享域（同时服务 APL={'/'.join(levels)}）")

    if allowed:
        who = (f"{len(sehap.domains())} 个应用域中，{len(allowing) + 1} 个"
               "允许该访问（含 scontext 自身）")
    elif allowing:
        who = (f"除 scontext 外的 {len(sehap.domains()) - 1} 个应用域中，"
               f"{len(allowing)} 个允许该访问")
    else:
        who = (f"除 scontext 外的 {len(sehap.domains()) - 1} 个应用域"
               "均不允许该访问")
    evidence = [
        who,
        f"更高 APL 等级已允许：{'、'.join(higher)}" if higher
        else "没有任何更高 APL 等级允许该访问",
    ]
    if uncovered:
        evidence.append(f"{len(uncovered)} 个应用域不在本策略语料中，无法查询"
                        f"（{', '.join(sorted(uncovered)[:4])}）")
    if multi_level:
        evidence.append(f"该域同时服务多个 APL 等级（{'/'.join(levels)}），"
                        "无法把拒绝归因到某一等级")
    if unknown_apl:
        evidence.append(f"APL 等级「{'/'.join(levels)}」不在已建模的阶梯"
                        f"（{'/'.join(sorted(APL_ORDER, key=apl_rank))}）中，"
                        "不判断是否为分级边界")
    if pair["kind"] == "sibling":
        evidence.append(
            f"调试/发布域对照：{'debuggable 域' if dbg else '普通域'}「{src}」被拒，"
            f"对照域「{pair['domain']}」{'允许' if pair['allows'] else '同样拒绝'}")
    if pair["kind"] == "same_domain":
        evidence.append(f"「{src}」本身同时声明了普通与 debuggable 两种情形"
                        "（同域，debuggable 只改变数据文件类型）")

    # A placeholder target cannot be patched (M3): the rule has to name the
    # concrete type the `service=` field resolves to. Say which one, rather
    # than print a rule against `default_service` that would compile and do
    # nothing.
    patch_tgt = resolved_tgt or tgt
    placeholder_note = (
        f"注意：日志里的目标「{tgt}」是 service 占位符，规则必须落在解析后的"
        f"具体类型「{patch_tgt}」上，写占位符本身落不了地（M3）"
        if patch_tgt != tgt else "")

    if allowed:
        fix_layer = "none"
        headline = (f"scontext「{src}」是应用域（APL={'/'.join(levels)}"
                    f"{'，debuggable' if dbg else ''}），{scope}。"
                    "该访问在策略中已被允许，跨层无需处理。")
        advice: list = []
    elif boundary:
        fix_layer = "app"
        headline = (
            f"scontext「{src}」是应用域（APL={'/'.join(levels)}），{scope}；"
            f"而该访问在更高 APL 上已被允许（{'、'.join(higher)}）"
            "—— 这更像 APL 分级边界，不是漏配的规则。")
        advice = [
            "应用层：先确认该应用是否应当以当前 APL 直接访问该系统资源。"
            "若确需，应提升应用 APL（签名 profile / module.json 的权限声明）"
            "或改由系统服务代理访问，而不是在系统层放开。",
            f"系统层：{src} 是共享域，`allow {src} {patch_tgt}:{cls} "
            f"{{ {' '.join(perms)} }};` 的受益者是该等级的全部应用，"
            "等于把高等级能力下放，通常不是想要的修复。",
        ]
    else:
        fix_layer = "system"
        if allowing:
            others = "、".join(sorted(allowing)[:4])
            headline = (
                f"scontext「{src}」是应用域（APL={'/'.join(levels)}），{scope}；"
                f"该访问在 {len(allowing)} 个应用域上有先例（{others}），"
                "但没有任何更高 APL 允许它。")
        else:
            headline = (
                f"scontext「{src}」是应用域（APL={'/'.join(levels)}），{scope}；"
                f"{len(sehap.domains())} 个应用域（覆盖 "
                f"{len(sehap.apls_all())} 个 APL 等级）均未允许该访问。")
        advice = [
            f"系统层：跨应用等级一致的缺口，按最小权限补"
            f"`allow {src} {patch_tgt}:{cls} {{ {' '.join(perms)} }};`。",
            f"影响面须知：{src} 是共享域，该规则对该 APL 等级的全部应用生效；"
            "若只有本应用需要，应改走专用域或系统服务，避免扩大共享域权限。",
        ]
    if placeholder_note:
        advice.append(placeholder_note)

    return {
        "app": True,
        "domain": src,
        "apl": levels,
        "debuggable": dbg,
        "multi_level_domain": multi_level,
        "scope": scope,
        "target": tgt,
        "resolved_target": resolved_tgt or "",
        "perms": list(perms),
        "cls": cls,
        "fix_layer": fix_layer,
        "headline": headline,
        "advice": advice,
        "evidence": evidence,
        "variants": variants,
        "boundary": {
            "checked": len(sehap.domains()) - 1,
            "allowing": allowing,
            "higher_apl_allowing": higher,
            "uncovered": sorted(uncovered),
        },
        "debug_pair": pair,
    }
