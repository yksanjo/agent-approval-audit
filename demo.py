"""Synthetic demo: one disciplined trace, one sloppy trace. No network, no models."""
import approval_audit

disciplined = """\
{"type": "approval", "id": "a1", "tool": "email.send", "ts": 10.0, "ttl": 60}
{"type": "call", "id": "c1", "tool": "web.search", "ts": 11.0}
{"type": "call", "id": "c2", "tool": "email.send", "ts": 12.0}
"""

sloppy = """\
{"type": "call", "id": "c1", "tool": "payments.charge", "ts": 5.0}
{"type": "approval", "id": "a1", "tool": "calendar.delete", "ts": 6.0}
{"type": "approval", "id": "a2", "tool": "email.send", "ts": 7.0, "ttl": 10}
{"type": "call", "id": "c2", "tool": "email.send", "ts": 8.0}
{"type": "call", "id": "c3", "tool": "email.send", "ts": 30.0}
"""

for name, text in (("disciplined", disciplined), ("sloppy", sloppy)):
    print(f"--- {name} trace ({text.count(chr(10))} records) ---")
    print(approval_audit.format_findings(approval_audit.audit_text(text)))
    print()
