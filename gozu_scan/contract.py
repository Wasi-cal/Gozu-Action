"""The Gozu ticket contract: title, identity and labels. Same rules as gozu, Gozurion and veil."""

from __future__ import annotations

import hashlib

from .models import Finding, Severity

TITLE_MAX_LENGTH = 120
_IDENTITY_HASH_LENGTH = 20

SEVERITY_TO_PRIORITY = {
    Severity.CRITICAL: "Highest",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Low",
}

# Directories no ticket is made for, at any depth.
_IGNORED_DIRECTORIES = frozenset({".github"})


def is_ignored_path(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")[:-1]
    return any(part in _IGNORED_DIRECTORIES for part in parts)


def ticket_title(repo: str, path: str, line: int | None, title: str) -> str:
    """ "repo | file.py | 42 | Rule title", at most 120 characters."""
    parts = [repo.strip().split("/")[-1], path.strip().split("/")[-1]]
    if line is not None:
        parts.append(str(line))
    head = " | ".join(parts) + " | "
    text = " ".join(title.split())
    if len(head) + len(text) <= TITLE_MAX_LENGTH:
        return head + text
    room = max(TITLE_MAX_LENGTH - len(head) - 3, 10)
    return head + text[:room].rstrip() + "..."


def finding_identity(finding: Finding) -> str:
    """The same rule at the same file and line of the same repo is one issue, on every branch."""
    parts = [
        finding.repo_full_name,
        finding.component,
        str(finding.line),
        finding.rule_key or "",
        finding.finding_type,
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:_IDENTITY_HASH_LENGTH]


def issue_label(finding: Finding) -> str:
    return f"issue-{finding_identity(finding)}"


def _label_value(value: str) -> str:
    return value.strip().lower().replace(" ", "-")


def branch_label(branch: str) -> str:
    return f"branch-{_label_value(branch)}"


def ticket_labels(finding: Finding) -> list[str]:
    return [issue_label(finding), _label_value(finding.source_tool), branch_label(finding.branch)]
