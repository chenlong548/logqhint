#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logqhint - 本地日志快速提示工具

扫描本地日志文件，按内置规则匹配常见错误与安全线索
（多次认证失败、异常堆栈、SQL 注入尝试、扫描行为等），
输出摘要提示。纯 Python 标准库，单文件实现。

作为 DKail 的配套轻量快速筛查工具：
- DKail 负责实时监控，logqhint 负责事后快速筛查。

用法:
    python logqhint.py <日志文件或目录> [选项]

选项:
    --format text|json     输出格式（默认 text）
    --top N                摘要只显示前 N 条提示（默认 10）
    --severity low|mid|high 最低严重级别（默认 low）
    --rules                列出内置规则后退出
    --follow-tail N        每个文件只读末尾 N 行（大文件提速，默认不限）

示例:
    python logqhint.py /var/log --severity mid
    python logqhint.py auth.log --format json --top 5
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# 内置规则：每条规则 = (id, 严重级别, 类别, 编译正则, 说明)
# severity: high > mid > low
# ---------------------------------------------------------------------------

def _c(pattern):
    return re.compile(pattern, re.IGNORECASE)

RULES = [
    # --- 认证 / 爆破 ---
    ("AUTH-FAIL", "mid", "认证",
     _c(r"(authentication failure|auth failure|failed password|login failed|invalid user)"),
     "认证失败（单条）"),
    ("AUTH-BRUTE", "high", "认证",
     _c(r"(failed password|authentication failure|invalid user|login failed)"),
     "认证失败（用于聚合计数，同一来源多次命中判为爆破）"),
    ("SUDO-DENY", "mid", "权限",
     _c(r"(sudo:.*command not allowed|user NOT in sudoers)"),
     "sudo 被拒绝，可能有越权尝试"),
    ("SSH-BADKEY", "low", "认证",
     _c(r"(error: .* in ssh(?:d)?|bad (?:publickey|password))"),
     "SSH 密钥/口令异常"),

    # --- Web 攻击特征 ---
    ("SQLI", "high", "Web攻击",
     _c(r"(union\s+select|or\s+1=1|'\s*or\s*'|\bselect\b.+\bfrom\b.+\-\-|\bsleep\s*\()"),
     "疑似 SQL 注入特征"),
    ("PATH-TRAVERSAL", "high", "Web攻击",
     _c(r"(\.\./){2,}|%2e%2e%2f|/etc/passwd|c:\\\\windows"),
     "疑似目录穿越/敏感文件探测"),
    ("CMD-INJECT", "high", "Web攻击",
     _c(r"(;\s*(?:cat|wget|curl|nc|bash|sh|rm)\b|\|\s*(?:cat|wget|curl|nc)\b|\$\((?:cat|wget|curl))"),
     "疑似命令注入特征"),
    ("WEB-SCAN", "low", "Web攻击",
     _c(r"(sqlmap|nikto|nmap|dirbuster|gobuster|masscan|acunetix|nessus)"),
     "已知扫描器 User-Agent / 特征"),
    ("XSS", "mid", "Web攻击",
     _c(r"(<script|javascript:|onerror\s*=)"),
     "疑似 XSS payload"),

    # --- 程序错误 / 堆栈 ---
    ("STACKTRACE", "mid", "程序错误",
     _c(r"(traceback \(most recent call last\)|at [a-z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)|Exception in thread)"),
     "异常堆栈"),
    ("LOG-ERROR", "low", "程序错误",
     _c(r"\b(?:ERROR|FATAL|CRITICAL)\b"),
     "ERROR/FATAL 级日志"),
    ("OOM-KILL", "high", "程序错误",
     _c(r"(out of memory|oom-killer|killed process)"),
     "内存耗尽 / OOM killer"),
    ("SEGFAULT", "mid", "程序错误",
     _c(r"segfault|segmentation fault"),
     "段错误"),

    # --- 安全事件 ---
    ("PRIV-ESC", "high", "安全事件",
     _c(r"(useradd|usermod|adduser|sudo:\s+.*USER=(?!.*COMMAND))"),
     "用户/提权相关操作"),
    ("SUSP-CRONTAB", "mid", "安全事件",
     _c(r"crontab.*\(root\)|RELOAD\s+\S*/crontabs?/"),
     "计划任务变更（root crontab）"),
    ("FW-DROP", "low", "安全事件",
     _c(r"(DROP|BLOCK|REJECT).*(SRC=|src=|from)"),
     "防火墙拦截记录"),
]

SEV_ORDER = {"low": 0, "mid": 1, "high": 2}


def iter_log_files(path):
    """path 是文件直接返回；目录则递归遍历文本类日志文件。"""
    if os.path.isfile(path):
        yield path
        return
    if not os.path.isdir(path):
        raise SystemExit(f"logqhint: 路径不存在: {path}")
    skip_ext = {".gz", ".zip", ".bz2", ".xz", ".tar", ".png", ".jpg", ".so", ".bin"}
    for root, _dirs, files in os.walk(path):
        for name in files:
            if os.path.splitext(name)[1].lower() in skip_ext:
                continue
            fp = os.path.join(root, name)
            try:
                if os.path.getsize(fp) == 0:
                    continue
            except OSError:
                continue
            yield fp


def read_lines(path, tail=None):
    """按行读取，忽略解码错误；tail 限 N 行时用定长缓冲只保留末尾。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if tail is None:
                return f.readlines()
            from collections import deque
            return list(deque(f, maxlen=tail))
    except OSError as e:
        print(f"logqhint: 跳过 {path}: {e}", file=sys.stderr)
        return []


# 爆破聚合：从 AUTH-BRUTE 行里尽量提取来源（IP 或 user=xxx）
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|for)\s+(?:invalid user\s+)?(\S+)", re.IGNORECASE)


def _extract_source(line):
    m = _IP_RE.search(line)
    if m:
        return m.group(0)
    m = _USER_RE.search(line)
    if m:
        return "user:" + m.group(1)
    return "(unknown)"


def scan_file(path, min_sev, tail):
    """扫描单个文件，返回 (findings, brute_counter)
    findings: list of dict(rule, severity, category, count, samples[最多2条])"""
    counts = {}   # rule_id -> [count, sample1, sample2]
    brute = Counter()
    for line in read_lines(path, tail):
        line = line.rstrip("\r\n")
        if not line:
            continue
        for rid, sev, cat, rx, desc in RULES:
            if SEV_ORDER[sev] < min_sev:
                continue
            if rx.search(line):
                slot = counts.setdefault(rid, [0, None, None])
                slot[0] += 1
                if slot[1] is None:
                    slot[1] = line
                elif slot[2] is None:
                    slot[2] = line
                if rid == "AUTH-BRUTE":
                    brute[_extract_source(line)] += 1
    findings = []
    for rid, (cnt, s1, s2) in counts.items():
        rule = next(r for r in RULES if r[0] == rid)
        samples = [s for s in (s1, s2) if s]
        findings.append({
            "rule": rid,
            "severity": rule[1],
            "category": rule[2],
            "description": rule[4],
            "count": cnt,
            "file": path,
            "samples": samples,
        })
    return findings, brute


def main():
    ap = argparse.ArgumentParser(
        prog="logqhint",
        description="本地日志快速提示工具：规则匹配错误与安全线索，输出摘要。")
    ap.add_argument("path", nargs="?", help="日志文件或目录")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--severity", choices=["low", "mid", "high"], default="low")
    ap.add_argument("--rules", action="store_true", help="列出内置规则")
    ap.add_argument("--follow-tail", type=int, default=None,
                    metavar="N", help="每文件只读末尾 N 行")
    args = ap.parse_args()

    if args.rules:
        out = [{"id": r[0], "severity": r[1], "category": r[2], "desc": r[4]}
               for r in RULES]
        print(json.dumps(out, ensure_ascii=False, indent=2)
              if args.format == "json" else
              "\n".join(f"{r[0]:<16} {r[1]:<5} [{r[2]}] {r[4]}" for r in RULES))
        return 0

    if not args.path:
        ap.error("缺少待扫描路径（或使用 --rules 查看规则）")
    min_sev = SEV_ORDER[args.severity]

    all_findings, brute_total = [], Counter()
    files_scanned = 0
    for fp in iter_log_files(args.path):
        files_scanned += 1
        f, b = scan_file(fp, min_sev, args.follow_tail)
        all_findings.extend(f)
        brute_total.update(b)

    # 爆破提示：来源命中 >= 5 次 → high
    brute_findings = []
    for src, cnt in brute_total.most_common(20):
        if cnt >= 5:
            brute_findings.append({
                "rule": "BRUTE-SUSPECT",
                "severity": "high",
                "category": "认证",
                "description": f"疑似口令爆破：来源 {src} 认证失败 {cnt} 次",
                "count": cnt,
                "file": "(聚合)",
                "samples": [],
            })

    # 排序：严重级别降序 → 次数降序
    all_findings = brute_findings + all_findings
    all_findings.sort(key=lambda x: (-SEV_ORDER[x["severity"]], -x["count"]))

    if args.format == "json":
        print(json.dumps({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": args.path,
            "files_scanned": files_scanned,
            "finding_groups": len(all_findings),
            "findings": all_findings[:args.top] if args.top > 0 else all_findings,
        }, ensure_ascii=False, indent=2))
        return 0

    # text 摘要
    print("=" * 62)
    print(f"logqhint 快速筛查摘要  目标: {args.path}")
    print(f"扫描文件: {files_scanned}   规则组命中: {len(all_findings)}")
    print("=" * 62)
    if not all_findings:
        print("未发现命中线索。")
        return 0
    shown = all_findings if args.top <= 0 else all_findings[:args.top]
    for f_ in shown:
        tag = {"high": "!!", "mid": " +", "low": "  "}[f_["severity"]]
        print(f"\n[{tag}] {f_['rule']} ({f_['severity']}/{f_['category']}) "
              f"命中 {f_['count']} 次  文件: {f_['file']}")
        print(f"      {f_['description']}")
        for s in f_["samples"]:
            print(f"      > {s[:160]}")
    hidden = len(all_findings) - len(shown)
    if hidden > 0:
        print(f"\n... 另有 {hidden} 组未显示（--top 调整）")
    return 0


if __name__ == "__main__":
    sys.exit(main())