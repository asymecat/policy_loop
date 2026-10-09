"""Root-cause attribution: one test per decision branch, plus the falsified axes.

The fixture is a hand-built board CIL small enough to reason about completely,
so a failure names the branch rather than "the number moved".

    app, other     <- members of the `domain` attribute
    permissive_dom <- `(typepermissive permissive_dom)`
    ghost                          (declared nowhere: absent symbol)

Object classes and types are different namespaces, and conflating them is the
bug this fixture used to have: `file` is the *class*, `sys_t` is the *type*.
Denial logs always name a class in `cls`, so `cls` must be a class here.

    classes: file, dir  (no third class -> a cls naming one is class-absent)
    type sys_t lacks `mounton`     (class-lacks-perm)
"""

import pytest

from policy_loop.attribution import (
    OWNER,
    RC_EMPTY_FIELD,
    RC_FIELD_SHIFT,
    RC_PLACEHOLDER,
    RC_GRANTED_ATTR,
    RC_GRANTED_DIRECT,
    RC_MALFORMED,
    RC_NO_CLASS,
    RC_NO_PERM,
    RC_NO_SYMBOL,
    RC_PARTIAL_GAP,
    RC_PERMISSIVE_DOMAIN,
    RC_PERM_UNKNOWN,
    RC_REDLINE,
    RC_UNATTRIBUTED,
    RC_VERSION_DRIFT,
    attribute,
    attribute_one,
    render_markdown,
)

# ---- board CIL -------------------------------------------------------------
BOARD_CIL = """
(class file (read write getattr))
(class dir (read search))
(type app)
(type other)
(type permissive_dom)
(type default_service)
(type sys_t)
(type dev_t)
(type stray_t)
(typeattribute domain)
(typepermissive permissive_dom)
(typeattributeset domain (app other))
(allow app sys_t (file (read write)))
(allow domain dev_t (file (read)))
"""

# ---- upstream .te tree -----------------------------------------------------
# `app sys_t:file { read write }` exists here, so a board denial of it is
# *drift*, not a gap. `stray_t` exists on the board but in no rule at all.
TREE = """
type app, domain;
type permissive_dom, domain;
type sys_t, file_type;
type dev_t, file_type;
type stray_t, file_type;
typeattribute domain;
allow app sys_t:file { read write };
"""


# ---- a fake PolicyIndex just rich enough for attribution -------------------
class _Rule:
    def __init__(self, raw, src, tgt, perms):
        self.raw, self.src, self.tgt, self.perms = raw, src, tgt, perms
        self.kind = "allow"


class _Index:
    """Mirrors the two PolicyIndex members attribution touches."""

    attributes = {"domain", "file"}

    def __init__(self, rules=()):
        self._rules = list(rules)

    def allow_rules(self, src, tgt, cls):
        # Real `allow_rules` is attribute-aware on both sides: a query for
        # `app` also hits a rule written against `domain`.
        return [r for r in self._rules
                if (src in r.src or r.src & {src, "domain"})
                and tgt in r.tgt]


@pytest.fixture
def board():
    from policy_loop.policy.cil import Board
    from pathlib import Path
    return Board(BOARD_CIL, Path("<fixture>"))


@pytest.fixture
def index():
    return _Index([
        # The upstream tree is *newer* than the board: it already grants
        # `getattr`, which the board's `(allow app sys_t (file (read write)))`
        # does not. That gap is drift, not a hole to patch.
        _Rule("allow app sys_t:file { read write getattr };", {"app"},
              {"sys_t"}, {"read", "write", "getattr"}),
        # a broad attribute rule -- the "attr" path
        _Rule("allow domain dev_t:file { read };", {"domain"}, {"dev_t"},
              {"read"}),
    ])


def _case(**kw):
    base = {"fp": "x", "count": 1, "category": "needs_human", "classification":
            "DOMAIN_OR_LABEL_MISMATCH", "src": "app", "tgt": "sys_t",
            "cls": "file", "perms": ["read"], "why": "",
            "enforcing": 1, "permissive": 0}
    base.update(kw)
    return base


def _rc(index, board, **kw):
    return attribute_one(index, board, _case(**kw)).root_cause


# ---- one branch at a time --------------------------------------------------

def test_redline_wins_over_everything(index, board):
    """A POTENTIAL_ESCALATION cluster is never re-explained as 'already fine'."""
    assert _rc(index, board, classification="POTENTIAL_ESCALATION") == RC_REDLINE


# ---- the well-formedness screen, which runs before any policy query ---------

@pytest.mark.parametrize("field", ["src", "tgt", "cls"])
def test_missing_field(index, board, field):
    """A record with no subject/target/class cannot name an access at all."""
    assert _rc(index, board, **{field: ""}) == RC_EMPTY_FIELD


def test_no_permissions_is_also_a_missing_field(index, board):
    assert _rc(index, board, perms=[]) == RC_EMPTY_FIELD


@pytest.mark.parametrize("name", ["file", "dir"])       # object classes
def test_class_name_in_a_type_slot(index, board, name):
    """`download_server sock_file sock_file` -- the columns shifted."""
    got = attribute_one(index, board, _case(tgt=name, perms=["read", "write"]))
    assert got.root_cause == RC_FIELD_SHIFT
    assert got.owner == "LOG"
    assert "对象类名" in got.detail


def test_permission_name_in_a_type_slot(index, board):
    """`resource_scheduler transfer transfer` -- a permission in the type slot."""
    got = attribute_one(index, board, _case(tgt="write", perms=["read"]))
    assert got.root_cause == RC_FIELD_SHIFT
    assert "权限名" in got.detail


def test_mls_level_in_the_target(index, board):
    """`u:charger_exec:s0` lost its role, so the target parsed as `s0`."""
    got = attribute_one(index, board, _case(tgt="s0"))
    assert got.root_cause == RC_MALFORMED
    assert got.owner == "LOG"


def test_placeholder_target(index, board):
    """A real board type, but one that must be resolved via `service=` first."""
    got = attribute_one(index, board, _case(tgt="default_service"))
    assert got.root_cause == RC_PLACEHOLDER
    assert got.owner == "TOOL"
    assert "service=" in got.detail


def test_screen_beats_the_policy_query(index, board):
    """The screen's whole job: a bad record must not get a confident answer.

    `dir` is a class here, and if the policy query ran first the board would
    simply deny it and the case would be reported as a real gap on a real
    type. It is neither.
    """
    got = attribute_one(index, board, _case(tgt="dir", perms=["search"]))
    assert got.root_cause != RC_PARTIAL_GAP
    assert got.root_cause == RC_FIELD_SHIFT


def test_absent_object_class(index, board):
    assert _rc(index, board, cls="no_such_class") == RC_NO_CLASS


def test_absent_symbol(index, board):
    assert _rc(index, board, src="ghost") == RC_NO_SYMBOL
    assert _rc(index, board, tgt="ghost") == RC_NO_SYMBOL


def test_class_lacks_permission(index, board):
    """`mounton` is not a `file` permission -- a typo, not a policy gap."""
    assert _rc(index, board, perms=["mounton"]) == RC_NO_PERM


def test_permissive_domain(index, board):
    """A permissive domain cannot emit an enforcing denial, so this is no gap."""
    got = attribute_one(index, board,
                        _case(src="permissive_dom", tgt="dev_t"))
    assert got.root_cause == RC_PERMISSIVE_DOMAIN
    assert got.owner == "NONE"


def test_already_granted_direct(index, board):
    got = attribute_one(index, board, _case(perms=["read", "write"]))
    assert got.root_cause == RC_GRANTED_DIRECT
    assert got.owner == "NONE"
    assert "allow app sys_t" in got.detail


def test_already_granted_via_attr(index, board):
    """`app` reaches dev_t only through the `domain` attribute rule."""
    got = attribute_one(index, board, _case(tgt="dev_t"))
    assert got.root_cause == RC_GRANTED_ATTR
    assert got.owner == "NONE"
    assert "domain" in got.detail


def test_version_drift(index, board):
    """Board denies, upstream tree allows -> the index is from a newer tree."""
    got = attribute_one(index, board, _case(tgt="sys_t", perms=["getattr"]))
    # `getattr` is a real `file` permission the board does not grant for
    # sys_t, and an upstream rule covering it exists -> drift, not a gap.
    assert got.root_cause == RC_VERSION_DRIFT
    assert got.owner == "TOOL"


def test_partial_gap_is_the_only_device_owner(index, board):
    """Board has the symbols, nothing upstream covers it, board denies it."""
    got = attribute_one(index, board, _case(tgt="stray_t", perms=["write"]))
    assert got.root_cause == RC_PARTIAL_GAP
    assert got.owner == "DEVICE"
    assert "write" in got.detail


def test_malformed_log_when_no_board(index):
    got = attribute_one(index, None, _case(why="目标上下文可疑: ???"))
    assert got.root_cause == RC_MALFORMED
    assert got.owner == "LOG"


def test_permissive_unknown_only_when_every_occurrence_lacks_it(index):
    got = attribute_one(index, None,
                        _case(count=4, permissive_unknown=4))
    assert got.root_cause == RC_PERM_UNKNOWN
    # 3 of 4 lacking it is not enough to claim the field is absent.
    got = attribute_one(index, None, _case(count=4, permissive_unknown=3))
    assert got.root_cause == RC_UNATTRIBUTED


def test_unattributed_is_not_silently_absorbed(index, board):
    """No board, no malformed sign, no permissive info -> must land in residual."""
    got = attribute_one(index, None, _case(count=2))
    assert got.root_cause == RC_UNATTRIBUTED
    assert got.owner == "TOOL"


# ---- report-level ----------------------------------------------------------

def _report(cases):
    return {"clusters": cases}


def test_ignores_non_human_buckets(index, board):
    rep = _report([
        _case(category="auto_repairable", perms=["mounton"]),
        _case(category="noise_or_already_allowed", perms=["mounton"]),
        _case(category="needs_human", perms=["mounton"]),
    ])
    res = attribute(rep, index=index, board=board, board_text=BOARD_CIL)
    assert res.total_clusters == 1


def test_owner_totals_partition_the_bucket(index, board):
    rep = _report([
        _case(src="permissive_dom", tgt="dev_t"),
        _case(tgt="stray_t", perms=["write"]),
        _case(cls="no_such_class"),
        _case(perms=["mounton"]),
        _case(classification="POTENTIAL_ESCALATION"),
        _case(perms=["read", "write"]),
    ])
    res = attribute(rep, index=index, board=board, board_text=BOARD_CIL)
    assert sum(res.by_owner.values()) == res.total_clusters == 6
    assert res.unattributed == 0 and res.complete


def test_no_board_is_marked_incomplete_and_says_so(index):
    res = attribute(_report([_case()]), index=index, board=None)
    assert not res.board_available
    assert res.items[0]["root_cause"] == RC_UNATTRIBUTED
    assert "残缺" in res.note


def test_corpus_provenance_is_detected(index, board):
    comments = "\n".join(f"# denial {i}" for i in range(5))
    res = attribute(_report([_case(perms=["read", "write"])]), index=index,
                    board=board, board_text=BOARD_CIL, corpus_text=comments)
    assert res.corpus_is_comments
    assert "历史 denial 记录" in res.note

    scraped = "avc: denied { read } for pid=1\navc: denied { write } for pid=2"
    res = attribute(_report([_case(perms=["read", "write"])]), index=index,
                    board=board, board_text=BOARD_CIL, corpus_text=scraped)
    assert not res.corpus_is_comments
    assert "设备采集" in res.note


def test_falsified_axes_carry_their_own_evidence(index, board):
    res = attribute(_report([_case(perms=["read", "write"])]), index=index,
                    board=board, board_text=BOARD_CIL)
    got = {f["axis"]: f for f in res.falsified_axes}
    assert got["boolean 未开"]["occurrences"] == 0
    assert got["constraint 拦下"]["occurrences"] == 0
    assert got["MLS 级不匹配"]["occurrences"] == 0
    assert all(f["verdict"] == "本平台不存在" for f in got.values())


def test_falsified_axes_report_presence_when_present(index, board):
    """The check must be able to fail -- otherwise it is decoration."""
    res = attribute(_report([_case(perms=["read", "write"])]), index=index,
                    board=board,
                    board_text=BOARD_CIL + "\n(boolean foo true)\n"
                                          "(constrain (dev_file (read)))\n")
    got = {f["axis"]: f["occurrences"] for f in res.falsified_axes}
    assert got["boolean 未开"] == 1
    assert got["constraint 拦下"] == 1


# ---- the DEVICE bucket, which is the only actionable one -------------------

def test_device_findings_group_by_domain_and_class(index, board):
    """Three cases on one (domain, class) are one work item, not three rows."""
    rep = _report([
        _case(tgt="stray_t", perms=["read"], count=2, enforcing=2),
        _case(tgt="stray_t", perms=["write"]),
    ])
    res = attribute(rep, index=index, board=board, board_text=BOARD_CIL)
    assert res.by_owner.get("DEVICE") == 2
    assert len(res.device_findings) == 1
    only = res.device_findings[0]
    assert (only["src"], only["cls"], only["tgts"]) == ("app", "file",
                                                       ["stray_t"])
    assert only["perms"] == ["read", "write"]
    assert only["cases"] == 2 and only["denials"] == 3
    assert only["enforcing"] == 3


def test_device_findings_count_enforcing_separately(index, board):
    """`permissive=1` denials never blocked anything -- they must not inflate it."""
    rep = _report([
        _case(tgt="stray_t", perms=["read"], count=2, enforcing=2),
        _case(tgt="stray_t", perms=["write"], count=5, enforcing=0,
              permissive=5),
    ])
    res = attribute(rep, index=index, board=board, board_text=BOARD_CIL)
    only = res.device_findings[0]
    assert only["denials"] == 7 and only["enforcing"] == 2
    md = "\n".join(render_markdown(res))
    assert "permissive=0" in md and "| 2 |" in md


def test_device_findings_separate_by_class(index, board):
    rep = _report([
        _case(tgt="stray_t", perms=["read"], cls="file"),
        _case(tgt="stray_t", perms=["read"], cls="dir"),
    ])
    res = attribute(rep, index=index, board=board, board_text=BOARD_CIL)
    assert {f["cls"] for f in res.device_findings} == {"file", "dir"}


def test_no_device_findings_says_so_explicitly(index, board):
    """An empty actionable bucket is the headline; it must not render as blank."""
    res = attribute(_report([_case(perms=["read", "write"])]), index=index,
                    board=board, board_text=BOARD_CIL)
    assert res.device_findings == []
    assert "这一档为空" in "\n".join(render_markdown(res))


def test_device_section_lists_the_permissions(index, board):
    res = attribute(_report([_case(tgt="stray_t", perms=["write"])]),
                    index=index, board=board, board_text=BOARD_CIL)
    md = "\n".join(render_markdown(res))
    assert "stray_t" in md and "`write`" in md and "唯一需要动手的一类" in md


def test_note_names_the_index_it_judged_against(index, board):
    res = attribute(_report([_case(perms=["read", "write"])]), index=index,
                    board=board, board_text=BOARD_CIL,
                    index_path="/some/tree/sepolicy")
    assert res.index_path == "/some/tree/sepolicy"
    assert "/some/tree/sepolicy" in res.note
    # Only DEVICE is stable across trees; the note has to say so.
    assert "DEVICE" in res.note and "随这棵树变化" in res.note


def test_owner_map_covers_every_root_cause():
    from policy_loop import attribution as A
    for name in dir(A):
        if name.startswith("RC_"):
            assert getattr(A, name) in OWNER, name


def test_markdown_renders_every_root_cause_seen(index, board):
    rep = _report([_case(tgt="stray_t", perms=["write"]),
                   _case(src="permissive_dom", tgt="dev_t")])
    res = attribute(rep, index=index, board=board, board_text=BOARD_CIL)
    md = "\n".join(render_markdown(res))
    for rc in res.by_root_cause:
        assert rc in md
    assert "该谁修" in md
