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

Standard-library `unittest` only: the README promises the suite runs with no
extra dependencies, and the interpreter it tells you to use (3.12) has no
pytest installed. Plain `assert` becomes `self.assert*` so a failure still
names the branch.
"""

import unittest

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


def _make_board():
    from policy_loop.policy.cil import Board
    from pathlib import Path
    return Board(BOARD_CIL, Path("<fixture>"))


def _make_index():
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


def _report(cases):
    return {"clusters": cases}


class TestAttribution(unittest.TestCase):
    """Every branch of `attribute_one`, then the report-level aggregation."""

    def setUp(self):
        self.index = _make_index()
        self.board = _make_board()

    # ---- one branch at a time ----------------------------------------------

    def test_redline_wins_over_everything(self):
        """A POTENTIAL_ESCALATION cluster is never re-explained as 'already fine'."""
        self.assertEqual(
            _rc(self.index, self.board,
                classification="POTENTIAL_ESCALATION"), RC_REDLINE)

    # ---- the well-formedness screen, which runs before any policy query -----

    def test_missing_src_field(self):
        """A record with no subject cannot name an access at all."""
        self.assertEqual(_rc(self.index, self.board, src=""), RC_EMPTY_FIELD)

    def test_missing_tgt_field(self):
        self.assertEqual(_rc(self.index, self.board, tgt=""), RC_EMPTY_FIELD)

    def test_missing_cls_field(self):
        self.assertEqual(_rc(self.index, self.board, cls=""), RC_EMPTY_FIELD)

    def test_no_permissions_is_also_a_missing_field(self):
        self.assertEqual(_rc(self.index, self.board, perms=[]),
                         RC_EMPTY_FIELD)

    def _assert_class_name_in_a_type_slot(self, name):
        """`download_server sock_file sock_file` -- the columns shifted."""
        got = attribute_one(self.index, self.board,
                            _case(tgt=name, perms=["read", "write"]))
        self.assertEqual(got.root_cause, RC_FIELD_SHIFT)
        self.assertEqual(got.owner, "LOG")
        self.assertIn("对象类名", got.detail)

    def test_class_name_file_in_a_type_slot(self):
        self._assert_class_name_in_a_type_slot("file")

    def test_class_name_dir_in_a_type_slot(self):
        self._assert_class_name_in_a_type_slot("dir")

    def test_permission_name_in_a_type_slot(self):
        """`resource_scheduler transfer transfer` -- a permission in the type slot."""
        got = attribute_one(self.index, self.board,
                            _case(tgt="write", perms=["read"]))
        self.assertEqual(got.root_cause, RC_FIELD_SHIFT)
        self.assertIn("权限名", got.detail)

    def test_mls_level_in_the_target(self):
        """`u:charger_exec:s0` lost its role, so the target parsed as `s0`."""
        got = attribute_one(self.index, self.board, _case(tgt="s0"))
        self.assertEqual(got.root_cause, RC_MALFORMED)
        self.assertEqual(got.owner, "LOG")

    def test_placeholder_target(self):
        """A real board type, but one that must be resolved via `service=` first."""
        got = attribute_one(self.index, self.board,
                            _case(tgt="default_service"))
        self.assertEqual(got.root_cause, RC_PLACEHOLDER)
        self.assertEqual(got.owner, "TOOL")
        self.assertIn("service=", got.detail)

    def test_screen_beats_the_policy_query(self):
        """The screen's whole job: a bad record must not get a confident answer.

        `dir` is a class here, and if the policy query ran first the board would
        simply deny it and the case would be reported as a real gap on a real
        type. It is neither.
        """
        got = attribute_one(self.index, self.board,
                            _case(tgt="dir", perms=["search"]))
        self.assertNotEqual(got.root_cause, RC_PARTIAL_GAP)
        self.assertEqual(got.root_cause, RC_FIELD_SHIFT)

    def test_absent_object_class(self):
        self.assertEqual(_rc(self.index, self.board, cls="no_such_class"),
                         RC_NO_CLASS)

    def test_absent_symbol(self):
        self.assertEqual(_rc(self.index, self.board, src="ghost"),
                         RC_NO_SYMBOL)
        self.assertEqual(_rc(self.index, self.board, tgt="ghost"),
                         RC_NO_SYMBOL)

    def test_class_lacks_permission(self):
        """`mounton` is not a `file` permission -- a typo, not a policy gap."""
        self.assertEqual(_rc(self.index, self.board, perms=["mounton"]),
                         RC_NO_PERM)

    def test_permissive_domain(self):
        """A permissive domain cannot emit an enforcing denial, so this is no gap."""
        got = attribute_one(self.index, self.board,
                            _case(src="permissive_dom", tgt="dev_t"))
        self.assertEqual(got.root_cause, RC_PERMISSIVE_DOMAIN)
        self.assertEqual(got.owner, "NONE")

    def test_already_granted_direct(self):
        got = attribute_one(self.index, self.board,
                            _case(perms=["read", "write"]))
        self.assertEqual(got.root_cause, RC_GRANTED_DIRECT)
        self.assertEqual(got.owner, "NONE")
        self.assertIn("allow app sys_t", got.detail)

    def test_already_granted_via_attr(self):
        """`app` reaches dev_t only through the `domain` attribute rule."""
        got = attribute_one(self.index, self.board, _case(tgt="dev_t"))
        self.assertEqual(got.root_cause, RC_GRANTED_ATTR)
        self.assertEqual(got.owner, "NONE")
        self.assertIn("domain", got.detail)

    def test_version_drift(self):
        """Board denies, upstream tree allows -> the index is from a newer tree."""
        got = attribute_one(self.index, self.board,
                            _case(tgt="sys_t", perms=["getattr"]))
        # `getattr` is a real `file` permission the board does not grant for
        # sys_t, and an upstream rule covering it exists -> drift, not a gap.
        self.assertEqual(got.root_cause, RC_VERSION_DRIFT)
        self.assertEqual(got.owner, "TOOL")

    def test_partial_gap_is_the_only_device_owner(self):
        """Board has the symbols, nothing upstream covers it, board denies it."""
        got = attribute_one(self.index, self.board,
                            _case(tgt="stray_t", perms=["write"]))
        self.assertEqual(got.root_cause, RC_PARTIAL_GAP)
        self.assertEqual(got.owner, "DEVICE")
        self.assertIn("write", got.detail)

    def test_malformed_log_when_no_board(self):
        got = attribute_one(self.index, None,
                            _case(why="目标上下文可疑: ???"))
        self.assertEqual(got.root_cause, RC_MALFORMED)
        self.assertEqual(got.owner, "LOG")

    def test_permissive_unknown_only_when_every_occurrence_lacks_it(self):
        got = attribute_one(self.index, None,
                            _case(count=4, permissive_unknown=4))
        self.assertEqual(got.root_cause, RC_PERM_UNKNOWN)
        # 3 of 4 lacking it is not enough to claim the field is absent.
        got = attribute_one(self.index, None,
                            _case(count=4, permissive_unknown=3))
        self.assertEqual(got.root_cause, RC_UNATTRIBUTED)

    def test_unattributed_is_not_silently_absorbed(self):
        """No board, no malformed sign, no permissive info -> must land in residual."""
        got = attribute_one(self.index, None, _case(count=2))
        self.assertEqual(got.root_cause, RC_UNATTRIBUTED)
        self.assertEqual(got.owner, "TOOL")

    # ---- report-level ------------------------------------------------------

    def test_ignores_non_human_buckets(self):
        rep = _report([
            _case(category="auto_repairable", perms=["mounton"]),
            _case(category="noise_or_already_allowed", perms=["mounton"]),
            _case(category="needs_human", perms=["mounton"]),
        ])
        res = attribute(rep, index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        self.assertEqual(res.total_clusters, 1)

    def test_owner_totals_partition_the_bucket(self):
        rep = _report([
            _case(src="permissive_dom", tgt="dev_t"),
            _case(tgt="stray_t", perms=["write"]),
            _case(cls="no_such_class"),
            _case(perms=["mounton"]),
            _case(classification="POTENTIAL_ESCALATION"),
            _case(perms=["read", "write"]),
        ])
        res = attribute(rep, index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        self.assertEqual(sum(res.by_owner.values()),
                         res.total_clusters)
        self.assertEqual(res.total_clusters, 6)
        self.assertEqual(res.unattributed, 0)
        self.assertTrue(res.complete)

    def test_no_board_is_marked_incomplete_and_says_so(self):
        res = attribute(_report([_case()]), index=self.index, board=None)
        self.assertFalse(res.board_available)
        self.assertEqual(res.items[0]["root_cause"], RC_UNATTRIBUTED)
        self.assertIn("残缺", res.note)

    def test_corpus_provenance_is_detected(self):
        comments = "\n".join(f"# denial {i}" for i in range(5))
        res = attribute(_report([_case(perms=["read", "write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL, corpus_text=comments)
        self.assertTrue(res.corpus_is_comments)
        self.assertIn("历史 denial 记录", res.note)

        scraped = "avc: denied { read } for pid=1\navc: denied { write } for pid=2"
        res = attribute(_report([_case(perms=["read", "write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL, corpus_text=scraped)
        self.assertFalse(res.corpus_is_comments)
        self.assertIn("设备采集", res.note)

    def test_falsified_axes_carry_their_own_evidence(self):
        res = attribute(_report([_case(perms=["read", "write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        got = {f["axis"]: f for f in res.falsified_axes}
        self.assertEqual(got["boolean 未开"]["occurrences"], 0)
        self.assertEqual(got["constraint 拦下"]["occurrences"], 0)
        self.assertEqual(got["MLS 级不匹配"]["occurrences"], 0)
        self.assertTrue(all(f["verdict"] == "本平台不存在"
                            for f in got.values()))

    def test_falsified_axes_report_presence_when_present(self):
        """The check must be able to fail -- otherwise it is decoration."""
        res = attribute(_report([_case(perms=["read", "write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL + "\n(boolean foo true)\n"
                                                "(constrain (dev_file (read)))\n")
        got = {f["axis"]: f["occurrences"] for f in res.falsified_axes}
        self.assertEqual(got["boolean 未开"], 1)
        self.assertEqual(got["constraint 拦下"], 1)

    # ---- the DEVICE bucket, which is the only actionable one ---------------

    def test_device_findings_group_by_domain_and_class(self):
        """Three cases on one (domain, class) are one work item, not three rows."""
        rep = _report([
            _case(tgt="stray_t", perms=["read"], count=2, enforcing=2),
            _case(tgt="stray_t", perms=["write"]),
        ])
        res = attribute(rep, index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        self.assertEqual(res.by_owner.get("DEVICE"), 2)
        self.assertEqual(len(res.device_findings), 1)
        only = res.device_findings[0]
        self.assertEqual((only["src"], only["cls"], only["tgts"]),
                         ("app", "file", ["stray_t"]))
        self.assertEqual(only["perms"], ["read", "write"])
        self.assertEqual(only["cases"], 2)
        self.assertEqual(only["denials"], 3)
        self.assertEqual(only["enforcing"], 3)

    def test_device_findings_count_enforcing_separately(self):
        """`permissive=1` denials never blocked anything -- they must not inflate it."""
        rep = _report([
            _case(tgt="stray_t", perms=["read"], count=2, enforcing=2),
            _case(tgt="stray_t", perms=["write"], count=5, enforcing=0,
                  permissive=5),
        ])
        res = attribute(rep, index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        only = res.device_findings[0]
        self.assertEqual(only["denials"], 7)
        self.assertEqual(only["enforcing"], 2)
        md = "\n".join(render_markdown(res))
        self.assertIn("permissive=0", md)
        self.assertIn("| 2 |", md)

    def test_device_findings_separate_by_class(self):
        rep = _report([
            _case(tgt="stray_t", perms=["read"], cls="file"),
            _case(tgt="stray_t", perms=["read"], cls="dir"),
        ])
        res = attribute(rep, index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        self.assertEqual({f["cls"] for f in res.device_findings},
                         {"file", "dir"})

    def test_no_device_findings_says_so_explicitly(self):
        """An empty actionable bucket is the headline; it must not render as blank."""
        res = attribute(_report([_case(perms=["read", "write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        self.assertEqual(res.device_findings, [])
        self.assertIn("这一档为空", "\n".join(render_markdown(res)))

    def test_device_section_lists_the_permissions(self):
        res = attribute(_report([_case(tgt="stray_t", perms=["write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        md = "\n".join(render_markdown(res))
        self.assertIn("stray_t", md)
        self.assertIn("`write`", md)
        self.assertIn("唯一需要动手的一类", md)

    def test_note_names_the_index_it_judged_against(self):
        res = attribute(_report([_case(perms=["read", "write"])]),
                        index=self.index, board=self.board,
                        board_text=BOARD_CIL,
                        index_path="/some/tree/sepolicy")
        self.assertEqual(res.index_path, "/some/tree/sepolicy")
        self.assertIn("/some/tree/sepolicy", res.note)
        # Only DEVICE is stable across trees; the note has to say so.
        self.assertIn("DEVICE", res.note)
        self.assertIn("随这棵树变化", res.note)

    def test_owner_map_covers_every_root_cause(self):
        from policy_loop import attribution as A
        for name in dir(A):
            if name.startswith("RC_"):
                self.assertIn(getattr(A, name), OWNER, name)

    def test_markdown_renders_every_root_cause_seen(self):
        rep = _report([_case(tgt="stray_t", perms=["write"]),
                       _case(src="permissive_dom", tgt="dev_t")])
        res = attribute(rep, index=self.index, board=self.board,
                        board_text=BOARD_CIL)
        md = "\n".join(render_markdown(res))
        for rc in res.by_root_cause:
            self.assertIn(rc, md)
        self.assertIn("该谁修", md)


if __name__ == "__main__":
    unittest.main()
