"""A plain-English explanation and fix for a ticket, from the Anthropic Messages API (stdlib HTTP, no SDK)."""

from __future__ import annotations

import json
import urllib.request

from .models import Finding, Severity
from .snippet import withhold_code

URL = "https://api.anthropic.com/v1/messages"
MAX_TOKENS = 1024
# Only the findings that matter most get an explanation, as in gozu.
ELIGIBLE = (Severity.CRITICAL, Severity.HIGH)

_SYSTEM = (
    "You write short, plain-English explanations for Jira tickets created from security scanner findings. "
    "Given a rule's own guidance and (when available) the flagged code, explain in 2-4 sentences what the "
    "problem is and a concrete suggested fix. Write for a developer who will read this in a ticket "
    "description, not for the person who already knows the rule - no headers, no markdown, plain prose only."
)
_NO_SNIPPET = "Code snippet not available for this finding."
_WITHHELD = (
    "Code snippet withheld: this finding may contain a hardcoded credential, so the exact flagged text is "
    "never sent to this API. Explain the general risk and remediation without referring to a specific secret value."
)


def build_prompt(finding: Finding) -> str:
    parts = [f"Rule: {finding.title}", f"Scanner message: {finding.message}"]
    if finding.how_to_fix:
        parts.append(f"Rule-level remediation guidance:\n{finding.how_to_fix}")
    if withhold_code(finding):
        parts.append(_WITHHELD)
    elif finding.code_snippet:
        parts.append(f"Flagged code (around line {finding.line}):\n{finding.code_snippet}")
    else:
        parts.append(_NO_SNIPPET)
    return "\n\n".join(parts)


def explain(finding: Finding, api_key: str, model: str) -> str:
    body = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": _SYSTEM,
        "messages": [{"role": "user", "content": build_prompt(finding)}],
    }
    request = urllib.request.Request(
        URL,
        data=json.dumps(body).encode(),
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        data = json.load(response)
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()
