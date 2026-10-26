#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""logqhint tests — aligned with the module's real API (RULES / scan_file /
read_lines / iter_log_files / main). Rewritten 2026-10-26: the previous
cloud-generated tests invented APIs (parse_rules/match_line) that never
existed, so all 14 tests failed with AttributeError."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock

import logqhint

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def _write(tmp, name, text):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


class RulesTest(unittest.TestCase):
    def test_rules_shape(self):
        self.assertGreaterEqual(len(logqhint.RULES), 10)
        ids = [r[0] for r in logqhint.RULES]
        self.assertEqual(len(ids), len(set(ids)), "rule ids must be unique")
        for rid, sev, cat, rx, desc in logqhint.RULES:
            self.assertIn(sev, logqhint.SEV_ORDER)
            self.assertTrue(hasattr(rx, "search"), f"{rid} regex must be compiled")
            self.assertTrue(desc)

    def test_sev_order(self):
        self.assertLess(logqhint.SEV_ORDER["low"], logqhint.SEV_ORDER["mid"])
        self.assertLess(logqhint.SEV_ORDER["mid"], logqhint.SEV_ORDER["high"])

    def test_sqli_rule_matches_payload(self):
        sqli = next(r for r in logqhint.RULES if r[0] == "SQLI")
        self.assertIsNotNone(
            sqli[3].search("GET /a.php?id=1 UNION SELECT password FROM users--"))

    def test_scanner_rule_matches_tool_ua(self):
        scan = next(r for r in logqhint.RULES if r[0] == "WEB-SCAN")
        self.assertIsNotNone(scan[3].search("Mozilla/5.0 (compatible; sqlmap/1.7)"))


class ScanFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lqh_")

    def test_auth_fail_findings(self):
        p = _write(self.tmp, "auth.log",
                   "Jan 5 10:00:01 host sshd[9]: Failed password for root from 203.0.113.9 port 22\n"
                   "Jan 5 10:00:02 host sshd[9]: Failed password for root from 203.0.113.9 port 22\n")
        findings, brute = logqhint.scan_file(p, logqhint.SEV_ORDER["low"], None)
        by_rule = {f["rule"]: f for f in findings}
        self.assertIn("AUTH-FAIL", by_rule)
        self.assertEqual(by_rule["AUTH-FAIL"]["count"], 2)
        self.assertLessEqual(len(by_rule["AUTH-FAIL"]["samples"]), 2)
        self.assertEqual(by_rule["AUTH-FAIL"]["severity"], "mid")
        self.assertIn("203.0.113.9", brute)

    def test_severity_filter_excludes_low(self):
        p = _write(self.tmp, "app.log", "2026-01-05 ERROR disk full\n")
        findings, _ = logqhint.scan_file(p, logqhint.SEV_ORDER["mid"], None)
        self.assertNotIn("LOG-ERROR", {f["rule"] for f in findings})

    def test_empty_and_bad_lines_tolerated(self):
        p = _write(self.tmp, "weird.log", "\n\n\x00\xff\xfe binary junk \x00\n\n")
        findings, _ = logqhint.scan_file(p, logqhint.SEV_ORDER["low"], None)
        self.assertEqual(findings, [])

    def test_brute_aggregation_counts_by_source(self):
        lines = "".join(
            f"Jan 5 10:00:{i:02d} host sshd[9]: Failed password for invalid user admin from 198.51.100.7 port 22\n"
            for i in range(6))
        p = _write(self.tmp, "brute.log", lines)
        _, brute = logqhint.scan_file(p, logqhint.SEV_ORDER["low"], None)
        self.assertEqual(brute.get("198.51.100.7"), 6)


class ExtractSourceTest(unittest.TestCase):
    def test_ip_wins(self):
        self.assertEqual(logqhint._extract_source("from 1.2.3.4 port 22"), "1.2.3.4")

    def test_user_fallback(self):
        # "for <name>" 提取；"for user bob" 会先匹配到 "for"→"user"（实现的真实启发式）
        self.assertEqual(logqhint._extract_source("Failed password for bob"), "user:bob")
        self.assertEqual(
            logqhint._extract_source("Failed password for invalid user carl"), "user:carl")

    def test_unknown(self):
        self.assertEqual(logqhint._extract_source("nothing here"), "(unknown)")


class ReadLinesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lqh_")

    def test_tail_keeps_last_n(self):
        p = _write(self.tmp, "t.log", "".join(f"line{i}\n" for i in range(10)))
        self.assertEqual([l.strip() for l in logqhint.read_lines(p, tail=3)],
                         ["line7", "line8", "line9"])

    def test_missing_file_returns_empty(self):
        p = os.path.join(self.tmp, "nope.log")
        self.assertEqual(logqhint.read_lines(p), [])

    def test_bad_bytes_replaced(self):
        p = _write(self.tmp, "b.log", "ÿþ ok\n")
        self.assertEqual(len(logqhint.read_lines(p)), 1)


class IterLogFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lqh_")

    def test_file_passthrough(self):
        p = _write(self.tmp, "a.log", "x\n")
        self.assertEqual(list(logqhint.iter_log_files(p)), [p])

    def test_dir_skips_archives_and_empty(self):
        _write(self.tmp, "real.log", "content\n")
        _write(self.tmp, "old.gz", "junk")
        _write(self.tmp, "empty.log", "")
        got = {os.path.basename(p) for p in logqhint.iter_log_files(self.tmp)}
        self.assertEqual(got, {"real.log"})

    def test_missing_path_raises_sysexit(self):
        with self.assertRaises(SystemExit):
            list(logqhint.iter_log_files(os.path.join(self.tmp, "ghost")))


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lqh_")
        self.log = _write(self.tmp, "attack.log",
                          "Jan 5 10:00:01 h sshd[1]: Failed password for root from 9.9.9.9 port 22\n"
                          "Jan 5 10:00:02 h httpd: 1 UNION SELECT password FROM users--\n")

    def run_main(self, argv):
        buf = StringIO()
        with mock.patch.object(sys, "argv", ["logqhint"] + argv), \
                mock.patch.object(sys, "stdout", buf):
            rc = logqhint.main()
        return rc, buf.getvalue()

    def test_rules_listing_text_and_json(self):
        rc, out = self.run_main(["--rules"])
        self.assertEqual(rc, 0)
        self.assertIn("AUTH-FAIL", out)
        rc, out = self.run_main(["--rules", "--format", "json"])
        data = json.loads(out)
        self.assertTrue(any(r["id"] == "SQLI" for r in data))

    def test_json_output_contract(self):
        rc, out = self.run_main([self.log, "--format", "json", "--top", "5"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        for key in ("scanned_at", "target", "files_scanned", "finding_groups", "findings"):
            self.assertIn(key, data)
        self.assertEqual(data["files_scanned"], 1)
        self.assertGreaterEqual(data["finding_groups"], 2)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("SQLI", rules)
        self.assertLessEqual(len(data["findings"]), 5)

    def test_text_summary_has_rule_and_count(self):
        rc, out = self.run_main([self.log])
        self.assertEqual(rc, 0)
        self.assertIn("AUTH-FAIL", out)

    def test_brute_suspect_after_5_fails(self):
        lines = "".join(
            f"Jan 5 10:00:{i:02d} h sshd[1]: Failed password for root from 8.8.4.4 port 22\n"
            for i in range(5))
        p = _write(self.tmp, "brute.log", lines)
        rc, out = self.run_main([p, "--format", "json"])
        data = json.loads(out)
        brute = [f for f in data["findings"] if f["rule"] == "BRUTE-SUSPECT"]
        self.assertEqual(len(brute), 1)
        self.assertEqual(brute[0]["severity"], "high")

    def test_no_findings_message(self):
        clean = _write(self.tmp, "clean.log", "all normal\n")
        rc, out = self.run_main([clean])
        self.assertEqual(rc, 0)
        self.assertIn("未发现命中线索", out)

    def test_missing_path_arg_errors(self):
        with self.assertRaises(SystemExit):
            self.run_main([])


class CliEndToEndTest(unittest.TestCase):
    """Real subprocess run — the README usage example must match this output."""

    def test_subprocess_json(self):
        tmp = tempfile.mkdtemp(prefix="lqh_")
        log = os.path.join(tmp, "a.log")
        with open(log, "w", encoding="utf-8") as f:
            f.write("Jan 5 10:00:01 h sshd[1]: Failed password for root from 9.9.9.9\n")
        mod = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logqhint.py")
        proc = subprocess.run([sys.executable, mod, log, "--format", "json"],
                              capture_output=True, encoding="utf-8", errors="replace",
                              timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        data = json.loads(proc.stdout)
        self.assertGreaterEqual(data["finding_groups"], 1)


if __name__ == "__main__":
    unittest.main()
