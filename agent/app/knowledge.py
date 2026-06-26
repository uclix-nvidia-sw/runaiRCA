from __future__ import annotations

from pathlib import Path


def load_troubleshooting_cases(path: str, *, max_chars: int = 12000) -> str:
    if not path:
        return ""
    try:
        content = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if len(content) <= max_chars:
        return content
    return content[:max_chars].rstrip() + "\n\n[truncated]"
