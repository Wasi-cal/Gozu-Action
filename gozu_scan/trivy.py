"""Trivy `fs`: vulnerabilities, secrets and misconfigurations of a checkout."""

from __future__ import annotations

import json
import re
import subprocess

from .contract import is_ignored_path
from .models import Finding, ScanError, Severity

# UNKNOWN means "not scored yet". It maps to MEDIUM, not LOW, so a CVE that turns out critical is not hidden.
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.MEDIUM,
}


def _severity(raw: str | None) -> Severity:
    return _SEVERITY.get(raw or "", Severity.MEDIUM)


def _readable_title(vulnerability_id: str, pkg_name: str, title: str | None) -> str:
    """ "CVE-1 | pkg | Title". Trivy often repeats "pkg: " at the start of its title, so that is cut."""
    text = title or ""
    while True:
        stripped = re.sub(rf"^{re.escape(pkg_name)}\s*:\s*", "", text, flags=re.IGNORECASE)
        if stripped == text:
            break
        text = stripped
    parts = [vulnerability_id, pkg_name]
    if text and text != vulnerability_id:
        parts.append(text)
    return " | ".join(parts)


def _vulnerability(vuln: dict, target: str) -> Finding:
    vuln_id = vuln.get("VulnerabilityID", "")
    pkg = vuln.get("PkgName", "")
    return Finding(
        key=f"{vuln_id}|{pkg}|{target}",
        title=_readable_title(vuln_id, pkg, vuln.get("Title")),
        severity=_severity(vuln.get("Severity")),
        component=target,
        line=None,
        message=vuln.get("Description") or vuln.get("Title") or vuln_id,
        finding_type="vulnerability",
        deep_link=vuln.get("PrimaryURL") or f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
        source_tool="trivy",
        rule_key=vuln_id,
        package_name=pkg,
        installed_version=vuln.get("InstalledVersion"),
        # Trivy gives an empty string when no fix exists yet.
        fixed_version=vuln.get("FixedVersion") or None,
    )


def _secret(secret: dict, target: str) -> Finding:
    rule = secret.get("RuleID", "")
    title = secret.get("Title") or rule
    # Trivy's Match and Code fields hold the secret itself, so neither goes in a ticket.
    return Finding(
        key=f"{rule}|{target}|{secret.get('StartLine')}",
        title=f"Secret: {title}",
        severity=_severity(secret.get("Severity")),
        component=target,
        line=secret.get("StartLine"),
        message=f"Trivy found a secret ({title}). Rotate it, then remove it from the repository history.",
        finding_type="vulnerability",
        deep_link="https://trivy.dev/latest/docs/scanner/secret/",
        source_tool="trivy",
        rule_key=rule,
        sensitive=True,
    )


def _misconfiguration(misconf: dict, target: str) -> Finding:
    rule = misconf.get("ID") or misconf.get("AVDID", "")
    title = misconf.get("Title") or rule
    line = (misconf.get("CauseMetadata") or {}).get("StartLine") or None
    return Finding(
        key=f"{rule}|{target}|{line}",
        title=f"{rule} | {title}",
        severity=_severity(misconf.get("Severity")),
        component=target,
        line=line,
        message=misconf.get("Description") or misconf.get("Message") or title,
        finding_type="vulnerability",
        deep_link=misconf.get("PrimaryURL") or "https://avd.aquasec.com",
        source_tool="trivy",
        rule_key=rule,
        how_to_fix=misconf.get("Resolution") or None,
    )


def parse(output: str) -> list[Finding]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError as e:
        raise ScanError(f"trivy produced output that cannot be read: {e}") from e

    findings: list[Finding] = []
    for entry in data.get("Results") or []:
        target = entry.get("Target", "")
        if is_ignored_path(target):
            continue
        findings += [_vulnerability(v, target) for v in entry.get("Vulnerabilities") or []]
        findings += [_secret(s, target) for s in entry.get("Secrets") or []]
        findings += [_misconfiguration(m, target) for m in entry.get("Misconfigurations") or []]
    return findings


def scan(path: str, skip_dirs: str) -> list[Finding]:
    # No --exit-code: a non-zero exit then means the scan failed, never "findings exist".
    cmd = ["trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln,secret,misconfig"]
    if skip_dirs:
        cmd += ["--skip-dirs", skip_dirs]
    try:
        result = subprocess.run(cmd + [path], capture_output=True, text=True)
    except FileNotFoundError as e:
        raise ScanError("The `trivy` binary was not found on PATH.") from e
    if result.returncode != 0:
        raise ScanError(f"trivy exited with status {result.returncode}: {result.stderr.strip()}")
    return parse(result.stdout)
