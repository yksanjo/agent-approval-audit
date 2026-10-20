import unittest

from approval_audit import (
    Approval, Call, audit, audit_text, format_findings, parse_trace,
)


def call(id="c1", tool="email.send", ts=10.0, line=1):
    return Call(id, tool, ts, line)


def appr(id="a1", tool="email.send", ts=9.0, until=None, line=1):
    return Approval(id, tool, ts, until, line)


def codes(findings):
    return sorted(f.code for f in findings)


class ParseTests(unittest.TestCase):
    def test_valid_records(self):
        calls, approvals, findings = parse_trace([
            '{"type":"call","id":"c1","tool":"email.send","ts":10}',
            '{"type":"approval","id":"a1","tool":"email.send","ts":9}',
        ])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(approvals), 1)
        self.assertEqual(findings, [])

    def test_blank_lines_skipped(self):
        calls, approvals, findings = parse_trace(["", "  ", '{"type":"call","id":"c1","tool":"x","ts":1}'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(findings, [])

    def test_invalid_json(self):
        _, _, f = parse_trace(["{oops"])
        self.assertEqual(codes(f), ["bad-record"])

    def test_non_object(self):
        _, _, f = parse_trace(["[1,2]"])
        self.assertEqual(codes(f), ["bad-record"])

    def test_bad_type(self):
        _, _, f = parse_trace(['{"type":"note","id":"x","tool":"y"}'])
        self.assertEqual(codes(f), ["bad-record"])

    def test_missing_id(self):
        _, _, f = parse_trace(['{"type":"call","tool":"email.send"}'])
        self.assertEqual(codes(f), ["bad-record"])

    def test_missing_tool(self):
        _, _, f = parse_trace(['{"type":"call","id":"c1"}'])
        self.assertEqual(codes(f), ["bad-record"])

    def test_bad_ts(self):
        _, _, f = parse_trace(['{"type":"call","id":"c1","tool":"x","ts":"soon"}'])
        self.assertEqual(codes(f), ["bad-record"])

    def test_ttl_computes_until(self):
        _, approvals, f = parse_trace(['{"type":"approval","id":"a1","tool":"t","ts":5,"ttl":10}'])
        self.assertEqual(f, [])
        self.assertEqual(approvals[0].until, 15.0)

    def test_ttl_without_ts_rejected(self):
        _, _, f = parse_trace(['{"type":"approval","id":"a1","tool":"t","ttl":10}'])
        self.assertEqual(codes(f), ["bad-record"])

    def test_until_and_ttl_conflict(self):
        _, _, f = parse_trace(['{"type":"approval","id":"a1","tool":"t","ts":5,"ttl":10,"until":99}'])
        self.assertEqual(codes(f), ["bad-record"])

    def test_bool_ts_rejected(self):
        _, _, f = parse_trace(['{"type":"call","id":"c1","tool":"x","ts":true}'])
        self.assertEqual(codes(f), ["bad-record"])


class AuditTests(unittest.TestCase):
    def test_clean_coverage(self):
        f = audit([call()], [appr()])
        self.assertEqual(f, [])

    def test_unapproved_call(self):
        f = audit([call()], [])
        self.assertEqual(codes(f), ["unapproved-call"])

    def test_approved_late(self):
        f = audit([call(ts=10.0)], [appr(ts=11.0)])
        self.assertEqual(codes(f), ["approved-late"])

    def test_non_sensitive_ignored(self):
        f = audit([call(tool="web.search")], [])
        self.assertEqual(f, [])

    def test_case_insensitive_sensitivity(self):
        f = audit([call(tool="Email.SEND")], [])
        self.assertEqual(codes(f), ["unapproved-call"])

    def test_custom_sensitive_list(self):
        f = audit([call(tool="web.search")], [], sensitive=("search",))
        self.assertEqual(codes(f), ["unapproved-call"])

    def test_single_use_reuse_flagged(self):
        f = audit([call("c1", ts=10.0, line=1), call("c2", ts=11.0, line=2)], [appr(ts=9.0)])
        self.assertEqual(codes(f), ["reused-approval"])

    def test_two_approvals_cover_two_calls(self):
        f = audit(
            [call("c1", ts=10.0, line=1), call("c2", ts=12.0, line=2)],
            [appr("a1", ts=9.0), appr("a2", ts=11.0, line=2)],
        )
        self.assertEqual(f, [])

    def test_stale_approval(self):
        f = audit([call(ts=100.0)], [appr(ts=9.0, until=50.0)])
        self.assertEqual(codes(f), ["stale-approval"])

    def test_fresh_approval_within_until(self):
        f = audit([call(ts=40.0)], [appr(ts=9.0, until=50.0)])
        self.assertEqual(f, [])

    def test_unused_approval_info(self):
        f = audit([], [appr()])
        self.assertEqual(codes(f), ["unused-approval"])
        self.assertEqual(f[0].severity, "info")

    def test_approval_for_other_tool_does_not_cover(self):
        f = audit([call(tool="email.send")], [appr(tool="calendar.delete")])
        self.assertEqual(codes(f), ["unapproved-call", "unused-approval"])

    def test_unused_non_sensitive_approval_silent(self):
        f = audit([], [appr(tool="web.search")])
        self.assertEqual(f, [])

    def test_missing_timestamps_still_cover(self):
        f = audit([call(ts=None)], [appr(ts=None)])
        self.assertEqual(f, [])

    def test_late_approval_reports_earliest(self):
        f = audit([call(ts=5.0)], [appr("a1", ts=8.0), appr("a2", ts=9.0, line=2)])
        self.assertEqual(codes(f), ["approved-late"])
        self.assertIn("a1", f[0].message)

    def test_severity_mapping(self):
        f = audit([call()], [])
        self.assertEqual(f[0].severity, "error")
        f2 = audit([call("c1", ts=10.0, line=1), call("c2", ts=11.0, line=2)], [appr(ts=9.0)])
        self.assertEqual(f2[0].severity, "warning")


class EndToEndTests(unittest.TestCase):
    def test_audit_text_clean(self):
        text = (
            '{"type":"approval","id":"a1","tool":"email.send","ts":1}\n'
            '{"type":"call","id":"c1","tool":"email.send","ts":2}\n'
            '{"type":"call","id":"c2","tool":"web.search","ts":3}\n'
        )
        self.assertEqual(audit_text(text), [])

    def test_audit_text_mixed(self):
        text = (
            '{"type":"call","id":"c1","tool":"payments.charge","ts":2}\n'
            "{bad json\n"
        )
        self.assertEqual(codes(audit_text(text)), ["bad-record", "unapproved-call"])

    def test_format_clean(self):
        self.assertEqual(format_findings([]), "ok: every sensitive call had a valid approval")

    def test_format_orders_errors_first(self):
        text = (
            '{"type":"approval","id":"a1","tool":"email.send","ts":1}\n'
            '{"type":"call","id":"c1","tool":"payments.charge","ts":2}\n'
        )
        out = format_findings(audit_text(text))
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("error: unapproved-call"))
        self.assertTrue(lines[1].startswith("info: unused-approval"))

    def test_large_trace(self):
        lines = []
        for i in range(5000):
            lines.append(f'{{"type":"approval","id":"a{i}","tool":"email.send","ts":{2*i}}}')
            lines.append(f'{{"type":"call","id":"c{i}","tool":"email.send","ts":{2*i+1}}}')
        self.assertEqual(audit_text("\n".join(lines)), [])


if __name__ == "__main__":
    unittest.main()
