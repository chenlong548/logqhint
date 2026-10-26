# logqhint

Fast local log triage in a single Python file — scan logs for security clues
(brute-force attempts, SQL injection, web scans, stack traces, OOM kills) and
get a severity-ranked summary in seconds. Pure standard library, zero
dependencies.

Built as the companion quick-check tool for
[DKail](https://github.com/chenlong548/DKail) (real-time monitoring):
DKail watches, **logqhint answers "what just happened in this log?"**.

## Why

Server logs are huge and grepping them one pattern at a time is slow.
`logqhint` ships 16 built-in detection rules (auth failures, brute-force
aggregation, SQLi/path-traversal/command-injection signatures, known scanner
user-agents, stack traces, OOM/segfault, privilege changes, firewall drops),
scans one file or a whole directory tree, and prints only what matters —
ranked by severity, with sample lines attached.

## Quick Start

```bash
# scan a single log
python logqhint.py /var/log/auth.log

# whole directory, only mid/high severity, top 5
python logqhint.py /var/log --severity mid --top 5

# machine-readable output for scripts
python logqhint.py /var/log/auth.log --format json

# big files: read only the last 200 lines per file
python logqhint.py /var/log --follow-tail 200
```

No install step. Python 3.8+ required, nothing else.

## Example output

```
==============================================================
logqhint 快速筛查摘要  目标: /tmp/sample.log
扫描文件: 1   规则组命中: 4
==============================================================

[!!] AUTH-BRUTE (high/认证) 命中 2 次  文件: /tmp/sample.log
      认证失败（用于聚合计数，同一来源多次命中判为爆破）
      > Jan 5 10:00:01 h sshd[1]: Failed password for root from 9.9.9.9 port 22
      > Jan 5 10:00:02 h sshd[1]: Failed password for root from 9.9.9.9 port 22

[!!] SQLI (high/Web攻击) 命中 1 次  文件: /tmp/sample.log
      疑似 SQL 注入特征
      > Jan 5 10:00:03 h httpd: 1 UNION SELECT password FROM users--

[ +] AUTH-FAIL (mid/认证) 命中 2 次  文件: /tmp/sample.log
      认证失败（单条）
      > Jan 5 10:00:01 h sshd[1]: Failed password for root from 9.9.9.9 port 22
```

The JSON format (`--format json`) returns the same findings in a stable
contract, ready for `jq` or your own pipeline:

```json
{
  "scanned_at": "2026-10-26T09:05:52+00:00",
  "target": "/tmp/sample.log",
  "files_scanned": 1,
  "finding_groups": 4,
  "findings": [
    {
      "rule": "AUTH-BRUTE",
      "severity": "high",
      "category": "认证",
      "description": "认证失败（用于聚合计数，同一来源多次命中判为爆破）",
      "count": 2,
      "file": "/tmp/sample.log",
      "samples": [
        "Jan 5 10:00:01 h sshd[1]: Failed password for root from 9.9.9.9 port 22"
      ]
    }
  ]
}
```

## Rule highlights

| Rule | Severity | Matches |
| --- | --- | --- |
| `AUTH-BRUTE` | high | failed logins, aggregated per source IP — 5+ hits raise `BRUTE-SUSPECT` |
| `SQLI` | high | `UNION SELECT`, `OR 1=1`, `sleep()` probes |
| `PATH-TRAVERSAL` | high | `../../`, `/etc/passwd`, encoded traversal |
| `CMD-INJECT` | high | `; cat`, `| wget`, `$(curl)` patterns |
| `WEB-SCAN` | low | sqlmap / nikto / nmap / gobuster user-agents |
| `STACKTRACE` | mid | Python tracebacks, Java stack frames |
| `OOM-KILL` | high | out-of-memory, oom-killer kills |
| `PRIV-ESC` | high | useradd/usermod, sudo env manipulation |

Run `python logqhint.py --rules` for the full list with descriptions.

## Design notes

- **GBK/UTF-8 tolerant**: bytes that fail to decode are replaced, never fatal —
  real-world logs are messy.
- **Brute-force aggregation**: same-source failed logins are counted across the
  scan; a source with 5+ hits is escalated to a high-severity `BRUTE-SUSPECT`
  finding.
- **Tail mode**: `--follow-tail N` keeps a fixed-size buffer per file instead of
  reading everything, for multi-GB logs.
- **Single file, stdlib only**: copy `logqhint.py` onto any host and run it —
  that's the deployment story.

## Testing

```bash
python -m unittest discover -s tests -t tests
```

24 tests cover rule shape, severity filtering, brute aggregation, tail reading,
archive/empty-file skipping, the JSON contract, and a real subprocess CLI run.

## License

[MIT](LICENSE)
