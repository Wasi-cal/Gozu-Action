"""The code around a finding: read from the checkout, rendered as a PNG for the ticket."""

from __future__ import annotations

import io
from pathlib import Path

from .models import Finding

# Lines on each side of the flagged range. One window serves the LLM prompt and the PNG.
CONTEXT_LINES = 15

# Semgrep names hardcoded-credential rules in words, for example "detected-generic-api-key".
_CREDENTIAL_KEYWORDS = ("secret", "hardcoded")


def withhold_code(finding: Finding) -> bool:
    """True when the flagged line may itself be a secret, so its code must stay out of Jira and the LLM."""
    if finding.sensitive:
        return True
    rule = (finding.rule_key or "").lower()
    return any(word in rule for word in _CREDENTIAL_KEYWORDS)


def read_window(workdir: str, relative_path: str, line: int) -> tuple[str, int] | None:
    """(text, first line number), or None when the file cannot be read. Never reads outside the checkout."""
    root = Path(workdir).resolve()
    try:
        path = (root / relative_path).resolve()
        if not path.is_relative_to(root):
            return None
        lines = path.read_text(errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    start = max(1, line - CONTEXT_LINES)
    if not lines or start > len(lines):
        return None
    end = min(len(lines), line + CONTEXT_LINES)
    return "\n".join(lines[start - 1 : end]), start


def attach_window(finding: Finding, workdir: str) -> None:
    """Sets the code snippet of a finding that has a line and no secret in it."""
    if finding.line is None or withhold_code(finding):
        return
    window = read_window(workdir, finding.component, finding.line)
    if window:
        finding.code_snippet, finding.code_snippet_start_line = window


def render_png(finding: Finding) -> bytes:
    """A syntax-highlighted PNG of the snippet, with the flagged line marked. Needs Pygments and Pillow."""
    from pygments import lexers
    from pygments.formatters import ImageFormatter
    from pygments.util import ClassNotFound

    if finding.code_snippet is None:
        raise ValueError(f"No code snippet for finding {finding.key}")
    code = finding.code_snippet
    start = finding.code_snippet_start_line or 1
    try:
        lexer = lexers.get_lexer_for_filename(finding.component, code)
    except ClassNotFound:
        lexer = lexers.TextLexer()
    formatter = ImageFormatter(
        encoding="utf-8",
        line_numbers=True,
        line_number_start=start,
        hl_lines=[(finding.line or start) - start + 1],
        font_size=16,
        line_pad=4,
    )
    buffer = io.BytesIO()
    formatter.format(lexer.get_tokens(code), buffer)
    return buffer.getvalue()
