"""avc 解析器测试。纯标准库断言,不依赖 pytest;直接 python 跑也行。

运行(在仓库根 ~/policy_loop):
    python3 -m policy_loop.avc.tests.test_parser
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(ROOT, "..", "..", ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from policy_loop.avc.parser import parse_record, iter_records  # noqa: E402
from policy_loop.avc.contexts import split_context, context_type  # noqa: E402

FIXTURE = os.path.join(ROOT, "fixtures", "real_samples.log")

# ---------- 单条用例:覆盖 4 种真实变体 + 畸形/噪音 ----------

S_AUDIT = ('type=1400 audit(1690000000.123:45): avc:  denied  { read } for  pid=1716 '
           'comm="surfaceflinger" name="main" dev="tmpfs" ino=1336 '
           'scontext=u:r:surfaceflinger:s0 tcontext=u:object_r:tmpfs:s0 tclass=file permissive=1')

S_MULTILINE = ('avc:  denied  { getattr } for  pid=741 comm="logd" name="logd" dev="dm-0" ino=942\n'
               '     scontext=u:r:logd:s0 tcontext=u:object_r:system_data_file:s0 tclass=file permissive=1')

S_MULTIPERM = ('avc:  denied  { read write open } for  pid=3124 comm="media_service" name="video0" dev="tmpfs" ino=2001 '
               'scontext=u:r:media_service:s0 tcontext=u:object_r:camera_device:s0 tclass=chr_file permissive=1')

S_EXTRAS = ('avc:  denied  { ioctl } for  pid=3124 comm="media_service" path="/dev/video0" dev="tmpfs" ino=2001 '
            'ioctlcmd=0x5601 scontext=u:r:media_service:s0 tcontext=u:object_r:camera_device:s0 '
            'tclass=chr_file permissive=0')

S_MLS = ('avc:  denied  { create } for  pid=918 comm="installd" name="test.apk" dev="sda1" ino=445566 '
         'scontext=u:r:installd:s0:c512,c768 tcontext=u:object_r:apk_data_file:s0 tclass=file permissive=1')

NOISE = "Binder: 1234_1: send error"
BAD_INCOMPLETE = "avc:  denied  { read } scontext=u:r:foo:s0 tclass=file permissive=1"


def test_audit_single_line():
    r = parse_record(S_AUDIT)
    assert r.parse_ok, r.error
    assert r.verdict == "denied"
    assert r.perms == ["read"]
    assert r.scontext_type() == "surfaceflinger"
    assert r.tcontext_type() == "tmpfs"
    assert r.tclass == "file"
    assert r.permissive == 1
    assert r.pid == 1716 and r.comm == "surfaceflinger"
    assert r.obj == {"name": "main", "dev": "tmpfs", "ino": 1336}
    assert r.ts == 1690000000.123 and r.audit_serial == 45


def test_multiline_continuation():
    r = parse_record(S_MULTILINE)
    assert r.parse_ok, r.error
    assert r.perms == ["getattr"]
    assert r.scontext == "u:r:logd:s0"
    assert r.tcontext == "u:object_r:system_data_file:s0"
    assert r.tclass == "file" and r.permissive == 1


def test_multi_perm_and_chr_file():
    r = parse_record(S_MULTIPERM)
    assert r.parse_ok, r.error
    assert r.perms == ["read", "write", "open"]
    assert r.scontext_type() == "media_service"
    assert r.tcontext_type() == "camera_device"
    assert r.tclass == "chr_file"


def test_extras_and_enforced():
    r = parse_record(S_EXTRAS)
    assert r.parse_ok, r.error
    assert r.perms == ["ioctl"]
    assert r.permissive == 0            # enforcing 已拦截
    assert r.obj.get("path") == "/dev/video0"
    assert r.extras.get("ioctlcmd") == "0x5601"


def test_mls_categories():
    r = parse_record(S_MLS)
    assert r.parse_ok, r.error
    assert r.scontext_type() == "installd"
    parts = split_context(r.scontext)
    assert parts["level"] == "s0:c512,c768"


def test_noise_and_bad_lines_do_not_crash():
    r = parse_record(NOISE)
    assert not r.parse_ok and r.error
    r2 = parse_record(BAD_INCOMPLETE)
    assert not r2.parse_ok and "tcontext" in r2.error


def test_end_to_end_fixture_split():
    text = open(FIXTURE, encoding="utf-8").read()
    recs = list(iter_records(text))                 # iter_records 产出原始字符串
    assert len(recs) == 6, f"期望 6 条有效记录,实际 {len(recs)}"
    for raw in recs:
        assert parse_record(raw).parse_ok, f"fixture 里出现坏记录: {raw!r}"
    # 噪音行(Binder / 无关内核行)不应被当成记录
    assert not any("Binder" in x or "ignore me" in x for x in recs)


def run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            fails += 1
            print(f"  FAIL  {t.__name__}: {e}")
    if fails:
        print(f"\n{fails} 个用例失败")
        sys.exit(1)
    print("\n全部用例通过 ✔")


if __name__ == "__main__":
    run_all()

    # 演示: 把带 ioctlcmd 的那条打成人话 JSON
    demo = parse_record(S_EXTRAS)
    print("\n===== 演示:一条 denial 解析成结构化 JSON =====")
    print(json.dumps(demo.to_json(), ensure_ascii=False, indent=2))
