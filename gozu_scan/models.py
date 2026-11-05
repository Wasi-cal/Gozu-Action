"""The finding every scanner produces and the Jira client turns into a ticket."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    key: str
    title: str
    severity: Severity
    component: str
    line: int | None
    message: str
    finding_type: str
    deep_link: str
    source_tool: str
    repo_full_name: str = ""
    branch: str = ""
    commit_sha: str = ""
    rule_key: str | None = None
    how_to_fix: str | None = None
    # A package finding has all three package fields and no line.
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    # True when the flagged text is itself a secret. Its code is never sent to an LLM or attached to a ticket.
    sensitive: bool = False
    # Source lines around the finding, read from the checkout. Set only for a ticket that is about to be made.
    code_snippet: str | None = None
    code_snippet_start_line: int | None = None
    llm_explanation: str | None = None


class ScanError(Exception):
    """A scanner could not run or gave output that cannot be read."""


class JiraError(Exception):
    """Jira refused a request or could not be reached."""
