#!/usr/bin/env python3
"""Reduce a raw Claude Code stream-json transcript to the parts that evidence gate A17.

    python scripts/sanitize_host_transcript.py <raw transcript.jsonl> <output.public.jsonl>

The raw stream also carries host environment metadata (installed skills, plugins, connectors,
working paths, timing and account details) that is not evidence and must not be published.
Kept: host version, model IDs, the user prompt, assistant text, every tool call (name and input)
and every tool result, plus the final result line's outcome fields. Dropped: everything else,
including model thinking and its signatures.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def sanitize(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        if not line.strip():
            continue
        ev = json.loads(line)
        kind = ev.get("type")
        if kind == "system" and ev.get("subtype") == "init":
            out.append({"type": "init", "claude_code_version": ev.get("claude_code_version"), "model": ev.get("model"),
                        "mcp_servers": [{"name": s.get("name"), "status": s.get("status")}
                                        for s in ev.get("mcp_servers") or []],
                        "nifimcp_tools": sorted(t for t in ev.get("tools") or [] if t.startswith("mcp__nifimcp__"))})
        elif kind in ("assistant", "user"):
            msg = ev.get("message") or {}
            blocks = []
            content = msg.get("content")
            if isinstance(content, str):
                blocks.append({"type": "text", "text": content})
            for b in content if isinstance(content, list) else []:
                t = b.get("type")
                if t == "text":
                    blocks.append({"type": "text", "text": b.get("text")})
                elif t == "tool_use":
                    blocks.append({"type": "tool_use", "id": b.get("id"), "name": b.get("name"), "input": b.get("input")})
                elif t == "tool_result":
                    blocks.append({"type": "tool_result", "tool_use_id": b.get("tool_use_id"),
                                   "is_error": b.get("is_error", False), "content": b.get("content")})
            if blocks:
                entry = {"type": kind, "content": blocks}
                if kind == "assistant" and msg.get("model"):
                    entry["model"] = msg["model"]
                out.append(entry)
        elif kind == "result":
            out.append({"type": "result", "subtype": ev.get("subtype"), "is_error": ev.get("is_error"),
                        "num_turns": ev.get("num_turns"), "result": ev.get("result")})
    return out


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 2:
        print(__doc__)
        return 2
    events = sanitize(Path(argv[0]).read_text(encoding="utf-8").splitlines())
    Path(argv[1]).write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events), encoding="utf-8")
    print(json.dumps({"events": len(events), "tool_calls": sum(1 for e in events for b in e.get("content") or []
                                                                 if b.get("type") == "tool_use")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
