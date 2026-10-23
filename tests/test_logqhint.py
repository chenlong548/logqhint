import io
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

import logqhint


def write_temp(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    f.write(textwrap.dedent(text))
    f.close()
    self_add_cleanup = f.name
    return self_add_cleanup


class RuleMatchingTest(unittest.TestCase):
    def setUp(self):
        self.rules_text = textwrap.dedent("""\
            # 注释行应被忽略
            [CRIT] Failed password
            [WARN] disk
            """)
        self.rules = logqhint.parse_rules(self.rules_text)

    def test_parse_rules_count_and_fields(self):
        self.assertEqual(len(self.rules), 2)
        crit = self.rules[0]
        self.assertEqual(crit["level"], "CRIT")
        self.assertIn("Failed password", crit["pattern"])

    def test_comment_and_blank_lines_skipped(self):
        lines = [ln for ln in self.rules_text.splitlines()]
        self.assertEqual(len(logqhint.parse_rules("\n\n".join(lines))), 2)

    def test_match_by_substring(self):
        hits = logqhint.match_line("Oct 23 10:00:01 host sshd: Failed password for root", self.rules)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["level"], "CRIT")

    def test_no_match_returns_empty(self):
        self.assertEqual(logqhint.match_line("normal systemd start", self.rules), [])

    def test_match_is_case_sensitive_by_default(self):
        self.assertEqual(logqhint.match_line("failed password for root", self.rules), [])


class AggregationTest(unittest.TestCase):
    def setUp(self):
        self.rules = logqhint.parse_rules("[CRIT] Failed password\n[WARN] disk")

    def _scan(self, lines):
        return logqhint.scan_lines(iter(lines), self.rules)

    def test_multi_event_grouped_by_rule(self):
        lines = [
            "sshd: Failed password for root from 1.2.3.4",
            "sshd: Failed password for admin from 5.6.7.8",
            "sshd: Failed password for root from 9.9.9.9",
            "kernel: disk I/O error on sda",
        ]
        events = self._scan(lines)
        self.assertEqual(len(events), 4)
        summary = logqhint.summarize(events)
        # CRIT 组应聚合到 3 次
        self.assertIn("3", summary)
        self.assertIn("CRIT", summary)
        # WARN 组 1 次
        self.assertIn("WARN", summary)

    def test_counts_match_events(self):
        lines = ["disk full"] * 5
        events = self._scan(lines)
        self.assertEqual(len(events), 5)
        summary = logqhint.summarize(events)
        self.assertIn("5", summary)

    def test_no_events_summary_is_clean(self):
        summary = logqhint.summarize(self._scan(["all good", "nothing here"]))
        self.assertEqual(summary.strip(), "")
        self.assertEqual(logqhint.summarize(self._scan([])).strip(), "")


class FaultToleranceTest(unittest.TestCase):
    def setUp(self):
        self.rules = logqhint.parse_rules("[CRIT] Failed password")

    def _scan_file(self, path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return logqhint.scan_lines(fh, self.rules)

    def test_empty_file_yields_no_events(self):
        path = write_temp("")
        try:
            self.assertEqual(self._scan_file(path), [])
        finally:
            os.unlink(path)

    def test_bad_lines_are_skipped_not_fatal(self):
        path = write_temp("""\
            \x00\xff\xfe binary junk
            Failed password for root
            \x00\x01more junk
            """)
        try:
            events = self._scan_file(path)
            # 坏行不应崩溃，好行仍被命中
            self.assertEqual(len(events), 1)
            self.assertIn("Failed password", events[0]["line"])
        finally:
            os.unlink(path)

    def test_missing_file_raises_clean_error(self):
        with self.assertRaises(FileNotFoundError):
            self._scan_file("/nonexistent/path/x.log")


class CliTest(unittest.TestCase):
    def setUp(self):
        self.rules_path = write_temp("[CRIT] Failed password\n[WARN] disk")
        self.log_path = write_temp("""\
            sshd: Failed password for root from 1.2.3.4
            sshd: Failed password for admin from 5.6.7.8
            kernel: disk error
            """)
        self.argv_backup = sys.argv

    def tearDown(self):
        sys.argv = self.argv_backup
        os.unlink(self.rules_path)
        os.unlink(self.log_path)

    def test_cli_prints_grouped_summary(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = logqhint.main(["logqhint", self.log_path, "--rules", self.rules_path])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("CRIT", text)
        self.assertIn("WARN", text)
        self.assertIn("2", text)  # CRIT 聚合 2 次

    def test_cli_clean_log_prints_nothing_and_exits_zero(self):
        clean = write_temp("all normal\n")
        try:
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = logqhint.main(["logqhint", clean, "--rules", self.rules_path])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue().strip(), "")
        finally:
            os.unlink(clean)

    def test_cli_bad_rules_file_reports_error(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = logqhint.main(["logqhint", self.log_path, "--rules", "/nonexistent.rules"])
        self.assertNotEqual(code, 0)
        self.assertIn("rules", err.getvalue().lower())