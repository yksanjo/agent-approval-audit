# agent-approval-audit

Offline approval-coverage audit for agent traces.

When an agent sends email, charges a card, or deletes something, someone should be able to answer afterwards: was that call approved, and was the approval still valid when it ran? This tool reads a recorded trace of tool calls and approval events, and reports which sensitive calls ran uncovered. It never runs an agent, never calls a model, and cannot grant or revoke approval for anything. It is an auditor, not a gate.

## Trace format

One JSON object per line, either a call or an approval:

```jsonl
{"type": "approval", "id": "a1", "tool": "email.send", "ts": 10.0, "ttl": 60}
{"type": "call",     "id": "c1", "tool": "email.send", "ts": 12.0}
```

- `type` - required, `"call"` or `"approval"`.
- `id` - required, non-empty string.
- `tool` - required, non-empty string. Approvals cover exactly one tool name.
- `ts` - optional finite number (seconds). Needed for late/stale findings.
- `ttl` or `until` - optional on approvals; expiry as a lifetime from `ts` or an absolute timestamp. At most one of the two.

Approvals are single-use: each one covers the earliest later uncovered call to its tool.

## What counts as sensitive

A call is sensitive when its tool name contains any of these substrings (case-insensitive): `send, pay, charge, delete, post, publish, share, invite, book, purchase, transfer, exec, deploy, submit, order`. Override with `--sensitive send,charge,delete` or the `sensitive=` argument. Non-sensitive calls are ignored.

## What it reports

| Code | Severity | Meaning |
| --- | --- | --- |
| `unapproved-call` | error | sensitive call with no approval for that tool anywhere |
| `approved-late` | error | every approval for that tool is timestamped after the call |
| `stale-approval` | error | the covering approval expired before the call ran |
| `reused-approval` | warning | more sensitive calls than single-use approvals; an earlier approval was stretched |
| `unused-approval` | info | a sensitive-tool approval that never covered any call |
| `bad-record` | error | malformed trace line |

## Usage

```bash
python3 approval_audit.py trace.jsonl
cat trace.jsonl | python3 approval_audit.py -
python3 approval_audit.py trace.jsonl --sensitive send,charge
python3 demo.py
python3 -m unittest test_approval_audit
```

Exit code is 1 when any finding is an error, else 0.

## Honest limits

- Static audit of a recorded trace. It cannot tell whether an approval was genuine, informed, or from the right person - only that a matching approval record exists in the trace.
- Sensitivity is substring matching on tool names. Tune `--sensitive` to your tool naming.
- Approvals bind to a tool name, not to specific arguments. An approval for `email.send` covers any `email.send` call; argument-scoped approvals are out of scope.
- Approvals with no `ts` are treated as covering any later call; calls with no `ts` skip ordering and expiry checks.
- The demo traces are synthetic.

## License

MIT
