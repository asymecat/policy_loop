"""avc 日志解析层: denial 文本 -> 结构化记录(AvcRecord)."""
from .contexts import split_context, context_type
from .model import AvcRecord
from .parser import parse_record, iter_records

__all__ = ["split_context", "context_type", "AvcRecord", "parse_record", "iter_records"]
