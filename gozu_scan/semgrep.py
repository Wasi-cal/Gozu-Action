"""Semgrep OSS: a local scan of a checkout. No semgrep.dev account is needed."""

from __future__ import annotations

import json
import subprocess

from .contract import is_ignored_path
from .models import Finding, ScanError, Severity

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "EXPERIMENT": Severity.INFO,
    "INVENTORY": Severity.INFO,
}


def _finding(raw: dict) -> Finding:
    check_id = raw.get("check_id", "")
    path = raw.get("path", "")
    line = (raw.get("start") or {}).get("line")
    extra = raw.get("extra") or {}
    location = f"{path}:{line}" if line is not None else path
    return Finding(
        key=f"semgrep:{check_id}|{path}|{line}",
        title=f"{check_id} ({location})",
        severity=_SEVERITY.get(extra.get("severity"), Severity.MEDIUM),
        component=path,
        line=line,
        message=extra.get("message", ""),
        finding_type="vulnerability",
        deep_link=f"https://semgrep.dev/r/{check_id}" if check_id else "https://semgrep.dev",
        source_tool="semgrep",
        rule_key=check_id or None,
    )


def parse(output: str) -> list[Finding]:
    try:
        data = json.loads(output or "{}")
    except json.JSONDecodeError as e:
        raise ScanError(f"semgrep produced output that cannot be read: {e}") from e
    return [_finding(r) for r in data.get("results", []) if not is_ignored_path(r.get("path", ""))]


def scan(path: str, config: str) -> list[Finding]:
    # The target is "." with cwd=path, so every result path is relative to the checkout.
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--json", "--config", config, "--quiet", "."],
            cwd=path,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise ScanError("The `semgrep` binary was not found on PATH.") from e
    # Exit 1 means findings exist. Only 2 and above is a failure.
    if result.returncode >= 2:
        raise ScanError(f"semgrep exited with status {result.returncode}: {result.stderr.strip()}")
    return parse(result.stdout)
