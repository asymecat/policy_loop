"""LogAgent: ingest raw denial text, structure it, and fingerprint it."""

from __future__ import annotations

import hashlib
import json

from policy_loop.agents.base import AgentResult, BaseAgent
from policy_loop.denial import parse as parse_denials


class LogAgent(BaseAgent):
    name = "LogAgent"

    def run(self, case) -> AgentResult:
        case.add_trace(self.name, "解析原始 denial", detail=case.denial_raw[:90])
        records = parse_denials(case.denial_raw)
        if not records:
            case.add_trace(self.name, "未找到 avc: denied 事件", status="fail")
            return AgentResult(self.name, ok=False,
                               summary="denial 无法解析", data={})
        rec = records[0].to_dict()
        case.record = rec

        # fingerprint for clustering/dedup (subject/target/class/perms)
        fp_src = hashlib.sha1(json.dumps({
            "src": rec.get("source_domain"),
            "tgt": rec.get("target_type"),
            "cls": rec.get("tclass"),
            "perms": rec.get("permissions"),
            "ioctl": rec.get("ioctl_cmd"),
        }, sort_keys=True).encode("utf-8")).hexdigest()[:12]

        detail = (f"{rec.get('source_domain')} -> {rec.get('target_type')}"
                  f":{rec.get('tclass')} {{{','.join(rec.get('permissions') or [])}}}"
                  + (f" ioctl={rec.get('ioctl_cmd')}" if rec.get("ioctl_cmd") else "")
                  + f"  [fp:{fp_src}]")
        case.add_trace(self.name, "结构化完成", detail=detail)
        return AgentResult(self.name, ok=True,
                           summary=f"已解析 {rec.get('source_domain')} → "
                                   f"{rec.get('target_type')}",
                           data={"record": rec, "fingerprint": fp_src})
