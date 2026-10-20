"""Offline approval-coverage audit for agent tool-call traces.

Reads a JSONL trace of tool calls and recorded approvals, then reports
which sensitive calls ran without a prior, valid, single-use approval.
It never runs an agent, never calls a model, and cannot grant or revoke
approval for anything. It is an auditor, not a gate.

Exit code is 1 when any finding has severity "error", else 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

DEFAULT_SENSITIVE = (
    "send", "pay", "charge", "delete", "post", "publish", "share",
    "invite", "book", "purchase", "transfer", "exec", "deploy",
    "submit", "order",
)


@dataclass
class Finding:
    code: str          # unapproved-call | approved-late | stale-approval | reused-approval | unused-approval | bad-record
    severity: str      # error | warning | info
    line: int          # 1-based trace line the finding is about
    message: str


@dataclass
class Call:
    id: str
    tool: str
    ts: float | None
    line: int


@dataclass
class Approval:
    id: str
    tool: str          # exact tool name this approval covers
    ts: float | None
    until: float | None  # absolute expiry ts, if any
    line: int
    used_by: list[str] = field(default_factory=list)


def _is_num(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and abs(x) != float("inf")


def parse_trace(lines: list[str]) -> tuple[list[Call], list[Approval], list[Finding]]:
    """Parse raw JSONL lines into calls, approvals, and parse findings."""
    calls: list[Call] = []
    approvals: list[Approval] = []
    findings: list[Finding] = []
    for n, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            findings.append(Finding("bad-record", "error", n, "line is not valid JSON"))
            continue
        if not isinstance(rec, dict):
            findings.append(Finding("bad-record", "error", n, "record is not a JSON object"))
            continue
        rtype = rec.get("type")
        if rtype not in ("call", "approval"):
            findings.append(Finding("bad-record", "error", n, f"type must be 'call' or 'approval', got {rtype!r}"))
            continue
        rid = rec.get("id")
        tool = rec.get("tool")
        if not isinstance(rid, str) or not rid:
            findings.append(Finding("bad-record", "error", n, "id must be a non-empty string"))
            continue
        if not isinstance(tool, str) or not tool:
            findings.append(Finding("bad-record", "error", n, "tool must be a non-empty string"))
            continue
        ts = rec.get("ts")
        if ts is not None and not _is_num(ts):
            findings.append(Finding("bad-record", "error", n, "ts must be a finite number"))
            continue
        ts = float(ts) if ts is not None else None
        if rtype == "call":
            calls.append(Call(rid, tool, ts, n))
        else:
            until = rec.get("until")
            ttl = rec.get("ttl")
            if until is not None and not _is_num(until):
                findings.append(Finding("bad-record", "error", n, "until must be a finite number"))
                continue
            if ttl is not None and not _is_num(ttl):
                findings.append(Finding("bad-record", "error", n, "ttl must be a finite number"))
                continue
            if until is not None and ttl is not None:
                findings.append(Finding("bad-record", "error", n, "use only one of until / ttl"))
                continue
            if ttl is not None:
                if ts is None:
                    findings.append(Finding("bad-record", "error", n, "ttl requires ts"))
                    continue
                until = ts + float(ttl)
            approvals.append(Approval(rid, tool, ts, float(until) if until is not None else None, n))
    return calls, approvals, findings


def audit(
    calls: list[Call],
    approvals: list[Approval],
    sensitive: tuple[str, ...] = DEFAULT_SENSITIVE,
) -> list[Finding]:
    """Check every sensitive call has a prior, unexpired, single-use approval."""
    findings: list[Finding] = []
    late_cited: set[int] = set()
    needles = tuple(s.lower() for s in sensitive)

    def is_sensitive(tool: str) -> bool:
        t = tool.lower()
        return any(n in t for n in needles)

    pool = sorted(approvals, key=lambda a: (a.ts is None, a.ts if a.ts is not None else 0.0, a.line))

    for call in calls:
        if not is_sensitive(call.tool):
            continue
        same_tool = [a for a in pool if a.tool == call.tool]
        prior = [a for a in same_tool if a.ts is None or call.ts is None or a.ts <= call.ts]
        if not prior:
            if same_tool:
                late_cited.update(id(a) for a in same_tool)
                findings.append(Finding(
                    "approved-late", "error", call.line,
                    f"call {call.id!r} to {call.tool!r} ran before its earliest approval "
                    f"(approval {same_tool[0].id!r} on line {same_tool[0].line})"))
            else:
                findings.append(Finding(
                    "unapproved-call", "error", call.line,
                    f"sensitive call {call.id!r} to {call.tool!r} has no approval anywhere in the trace"))
            continue
        # earliest unused prior approval covers this call (single-use)
        chosen = next((a for a in prior if not a.used_by), None)
        if chosen is None:
            findings.append(Finding(
                "reused-approval", "warning", call.line,
                f"call {call.id!r} to {call.tool!r} has no unused approval; "
                f"earliest approval {prior[0].id!r} already covered {len(prior[0].used_by)} call(s)"))
            chosen = prior[0]
        chosen.used_by.append(call.id)
        if chosen.until is not None and call.ts is not None and call.ts > chosen.until:
            findings.append(Finding(
                "stale-approval", "error", call.line,
                f"call {call.id!r} to {call.tool!r} ran at ts={call.ts:g} but approval "
                f"{chosen.id!r} expired at ts={chosen.until:g}"))

    for a in pool:
        if not a.used_by and id(a) not in late_cited and is_sensitive(a.tool):
            findings.append(Finding(
                "unused-approval", "info", a.line,
                f"approval {a.id!r} for {a.tool!r} never covered a call"))
    return findings


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "ok: every sensitive call had a valid approval"
    order = {"error": 0, "warning": 1, "info": 2}
    out = []
    for f in sorted(findings, key=lambda f: (order.get(f.severity, 3), f.line, f.code)):
        out.append(f"{f.severity}: {f.code}: {f.message} (line {f.line})")
    return "\n".join(out)


def audit_text(text: str, sensitive: tuple[str, ...] = DEFAULT_SENSITIVE) -> list[Finding]:
    calls, approvals, findings = parse_trace(text.splitlines())
    return findings + audit(calls, approvals, sensitive)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Offline approval-coverage audit for agent traces.")
    p.add_argument("trace", help="path to a JSONL trace, or '-' for stdin")
    p.add_argument("--sensitive", default=",".join(DEFAULT_SENSITIVE),
                   help="comma-separated substrings marking sensitive tool names")
    args = p.parse_args(argv)
    text = sys.stdin.read() if args.trace == "-" else open(args.trace, encoding="utf-8").read()
    sensitive = tuple(s.strip() for s in args.sensitive.split(",") if s.strip())
    findings = audit_text(text, sensitive)
    print(format_findings(findings))
    return 1 if any(f.severity == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
