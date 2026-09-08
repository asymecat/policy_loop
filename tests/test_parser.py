"""Tests for policy_loop.denial.parser (OpenHarmony AVC formats)."""

import unittest
from pathlib import Path

from policy_loop.denial import parse, parse_event

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "fixtures"


class TestParser(unittest.TestCase):
    def test_chr_file_ioctl(self):
        line = (
            'avc: denied { ioctl } for pid=7881, comm="/system/bin/faultloggerd" '
            'path="/dev/pdump" dev="" ino=23 ioctlcmd=0x7003 '
            "scontext=u:r:faultloggerd:s0 tcontext=u:object_r:dev_pdump:s0 "
            "tclass=chr_file permissive=1"
        )
        rec = parse_event(line)
        self.assertEqual(rec.source_domain, "faultloggerd")
        self.assertEqual(rec.target_type, "dev_pdump")
        self.assertEqual(rec.tclass, "chr_file")
        self.assertEqual(rec.permissions, ("ioctl",))
        self.assertEqual(rec.ioctl_cmd, "0x7003")
        self.assertIs(rec.permissive, True)
        self.assertEqual(rec.comm, "/system/bin/faultloggerd")
        self.assertEqual(rec.pid, 7881)

    def test_parameter_service(self):
        line = (
            "avc: denied { set } for parameter=persist.account.login_name_max "
            "pid=2208 uid=3058 gid=3058 scontext=u:r:accountmgr:s0 "
            "tcontext=u:object_r:persist_param:s0 tclass=parameter_service "
            "permissive=0"
        )
        rec = parse_event(line)
        self.assertEqual(rec.source_domain, "accountmgr")
        self.assertEqual(rec.target_type, "persist_param")
        self.assertEqual(rec.tclass, "parameter_service")
        self.assertEqual(rec.permissions, ("set",))
        self.assertEqual(rec.parameter, "persist.account.login_name_max")
        self.assertIs(rec.permissive, False)

    def test_samgr_class(self):
        line = (
            "avc: denied { get } for service=3508 "
            "sid=u:r:distributedfiledaemon:s0 "
            "scontext=u:r:distributedfiledaemon:s0 "
            "tcontext=u:object_r:sa_sandbox_manager_service:s0 "
            "tclass=samgr_class permissive=0"
        )
        rec = parse_event(line)
        self.assertEqual(rec.tclass, "samgr_class")
        self.assertEqual(rec.target_type, "sa_sandbox_manager_service")
        self.assertEqual(rec.service, "3508")
        self.assertIs(rec.permissive, False)

    def test_audit_prefix(self):
        line = (
            "audit: type=1400 audit(1502458430.566:4): avc:  denied  { open } "
            'for  pid=1658 comm="setenforce" path="/sys/fs/selinux/enforce" '
            "dev=\"selinuxfs\" ino=4 scontext=u:r:hdcd:s0 "
            "tcontext=u:object_r:selinuxfs:s0 tclass=file permissive=1"
        )
        rec = parse_event(line)
        self.assertEqual(rec.source_domain, "hdcd")
        self.assertEqual(rec.target_type, "selinuxfs")
        self.assertEqual(rec.tclass, "file")
        self.assertEqual(rec.permissions, ("open",))

    def test_avc_audit_slow_prefix(self):
        line = (
            "avc_audit_slow:260] avc: denied { getattr } for pid=4594, "
            'comm="/system/bin/appspawn"  path="/data/storage/el2/log/crashpad" '
            "dev=\"/dev/block/platform/fa500000.ufs/by-name/userdata\" ino=5159 "
            "scontext=u:r:debug_hap:s0 tcontext=u:object_r:data_app_el2_file:s0 "
            "tclass=dir permissive=1"
        )
        rec = parse_event(line)
        self.assertEqual(rec.source_domain, "debug_hap")
        self.assertEqual(rec.target_type, "data_app_el2_file")
        self.assertEqual(rec.tclass, "dir")

    def test_capability_class(self):
        line = (
            'avc: denied { chown } for pid=11524, comm="/system/bin/sa_main"  '
            "capability=0 scontext=u:r:backup_sa:s0 "
            "tcontext=u:r:backup_sa:s0 tclass=capability permissive=0"
        )
        rec = parse_event(line)
        self.assertEqual(rec.tclass, "capability")
        self.assertEqual(rec.source_domain, "backup_sa")
        self.assertEqual(rec.target_type, "backup_sa")

    def test_parse_multiple_events(self):
        text = (
            'avc: denied { read } for pid=1 comm="a" scontext=u:r:one:s0 '
            "tcontext=u:object_r:two:s0 tclass=file permissive=1\n"
            'avc: denied { write } for pid=2 comm="b" scontext=u:r:three:s0 '
            "tcontext=u:object_r:four:s0 tclass=file permissive=0"
        )
        recs = parse(text)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0].source_domain, "one")
        self.assertEqual(recs[1].source_domain, "three")

    def test_parse_fixture_file(self):
        text = (FIXTURES / "sample_denials.txt").read_text(encoding="utf-8")
        recs = parse(text)
        self.assertGreaterEqual(len(recs), 7)
        classes = {r.tclass for r in recs}
        self.assertIn("parameter_service", classes)
        self.assertIn("samgr_class", classes)

    def test_hash_prefixed_denial_comment_parses(self):
        # upstream .te files keep real denials as '#' comments; they must parse
        line = (
            "# avc:  denied  { lock } for  pid=4779 comm=\"IPC_1_4783\" "
            'path="/x" scontext=u:r:accountmgr:s0 '
            "tcontext=u:object_r:account_data_file:s0 tclass=file permissive=1"
        )
        recs = parse(line)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec.source_domain, "accountmgr")
        self.assertEqual(rec.target_type, "account_data_file")
        self.assertEqual(rec.permissions, ("lock",))

    def test_hash_prefix_still_filters_plain_comments(self):
        # but a bare '#' comment line between events must not be kept
        text = (
            "avc: denied { read } for pid=1 comm=\"a\" scontext=u:r:one:s0 "
            "tcontext=u:object_r:two:s0 tclass=file permissive=1\n"
            "# just a note, no avc marker\n"
            'avc: denied { write } for pid=2 comm="b" scontext=u:r:three:s0 '
            "tcontext=u:object_r:four:s0 tclass=file permissive=0"
        )
        recs = parse(text)
        self.assertEqual(len(recs), 2)
        self.assertNotIn("# just a note", recs[0].raw)


if __name__ == "__main__":
    unittest.main()
