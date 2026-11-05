"""Jira Cloud client: find tickets that already exist, create the ones that do not."""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass

from . import log
from .contract import SEVERITY_TO_PRIORITY, issue_label, ticket_labels, ticket_title
from .models import Finding, JiraError

# Jira rejects a description over 32,767 characters, so each free-text block stays well under it.
_TEXT_MAX_CHARS = 10000
# Labels in one dedupe search. Keeps the query short and the number of requests small.
_SEARCH_CHUNK = 40
_RETRIES = 3


def jql_quote(value: str) -> str:
    """A JQL string literal. A branch name can hold a quote or a backslash, so both are escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def key_number(key: str) -> int:
    return int(key.rsplit("-", 1)[-1])


@dataclass
class Issue:
    key: str
    labels: list[str]
    done: bool

    @property
    def number(self) -> int:
        return key_number(self.key)


def _issue(raw: dict) -> Issue:
    fields = raw.get("fields") or {}
    category = ((fields.get("status") or {}).get("statusCategory") or {}).get("key")
    return Issue(raw["key"], fields.get("labels") or [], category == "done")


def _truncate(text: str, limit: int = _TEXT_MAX_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


# Atlassian Document Format builders.
def _text(text: str) -> dict:
    return {"type": "text", "text": text}


def _paragraph(text: str) -> dict:
    return {"type": "paragraph", "content": [_text(text)]}


def _heading(text: str) -> dict:
    return {"type": "heading", "attrs": {"level": 3}, "content": [_text(text)]}


def _bullets(lines: list[str]) -> dict:
    return {"type": "bulletList", "content": [{"type": "listItem", "content": [_paragraph(line)]} for line in lines]}


def _code_block(text: str) -> dict:
    return {"type": "codeBlock", "attrs": {}, "content": [_text(text)]}


def _expand(title: str, *content: dict) -> dict:
    return {"type": "expand", "attrs": {"title": title}, "content": list(content)}


def _summarize(text: str, limit: int = 400) -> tuple[str, str | None]:
    """(short, full). `full` is None when the text already fits. The cut prefers a sentence end, then a word."""
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean, None
    window = clean[:limit]
    cut = max(window.rfind(". "), window.rfind("! "), window.rfind("? "))
    if cut < limit // 2:
        cut = window.rfind(" ")
    if cut < limit // 2:
        return window.rstrip() + "...", clean
    return window[: cut + 1].rstrip() + (" ..." if window[cut] != "." else ""), clean


def _recommended_action(finding: Finding) -> str | None:
    if finding.package_name:
        if finding.fixed_version:
            return f"Upgrade {finding.package_name} from {finding.installed_version} to {finding.fixed_version} or later."
        return (
            f"No fixed version of {finding.package_name} is available yet. "
            "Track the advisory and apply a mitigation until one is released."
        )
    if finding.line is not None:
        return f"Review {finding.component} at line {finding.line}."
    return None


def build_details(finding: Finding) -> list[str]:
    """The Details list of the ticket contract, in contract order. A line with no value is left out."""
    details = [f"Repository: {finding.repo_full_name}", f"Component: {finding.component}"]
    if finding.package_name:
        details += [
            f"Package: {finding.package_name}",
            f"Installed version: {finding.installed_version}",
            f"Fixed version: {finding.fixed_version or 'not yet available'}",
        ]
    if finding.line is not None:
        details.append(f"Line: {finding.line}")
    details.append(f"Type: {finding.finding_type}")
    if finding.rule_key:
        details.append(f"Rule: {finding.rule_key}")
    details += [
        f"Severity: {finding.severity.value}",
        f"Source: {finding.source_tool}",
        f"Branch: {finding.branch}",
    ]
    if finding.commit_sha:
        details.append(f"Commit: {finding.commit_sha[:10]}")
    return details


def build_description(finding: Finding) -> dict:
    short, full = _summarize(finding.llm_explanation or finding.message)
    content = [_paragraph(short)]
    if full:
        content.append(_expand("Full description", _paragraph(_truncate(full))))
    content += [_heading("Details"), _bullets(build_details(finding))]
    action = _recommended_action(finding)
    if action:
        content += [_heading("Recommended action"), _paragraph(action)]
    if finding.how_to_fix:
        content += [_heading("How to fix"), _code_block(_truncate(finding.how_to_fix))]
    return {"type": "doc", "version": 1, "content": content}


AUTO_CLOSED_LABEL = "gozu-auto-closed"


class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str, project_key: str):
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._sprint_id: int | None = None
        self._sprint_looked_up = False

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        body: dict | None = None,
        raw_body: bytes | None = None,
        headers: dict | None = None,
    ) -> dict:
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        for attempt in range(_RETRIES + 1):
            request = urllib.request.Request(url, data=data, headers={**self._headers, **(headers or {})}, method=method)
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")
                # Jira asks to slow down with 429, and 5xx can pass on its own. Nothing else is retried.
                if (e.code == 429 or e.code >= 500) and attempt < _RETRIES:
                    time.sleep(float(e.headers.get("Retry-After") or 2 ** (attempt + 1)))
                    continue
                if e.code in (401, 403):
                    raise JiraError(f"Jira {method} {path} failed with {e.code}. Check the token and the project permissions.") from e
                raise JiraError(f"Jira {method} {path} failed with {e.code}: {detail}") from e
            except urllib.error.URLError as e:
                if attempt < _RETRIES:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise JiraError(f"Jira {method} {path} could not be reached: {e.reason}") from e
        raise JiraError(f"Jira {method} {path} failed.")  # pragma: no cover

    def _search(self, jql: str):
        """Every issue of a query, with its labels and status. Follows the pages."""
        params = {"jql": jql, "fields": "labels,status", "maxResults": 100}
        while True:
            page = self._request("GET", "/rest/api/3/search/jql", params)
            yield from (_issue(raw) for raw in page.get("issues", []))
            if page.get("isLast", True) or not page.get("nextPageToken"):
                return
            params = {**params, "nextPageToken": page["nextPageToken"]}

    def existing_issues(self, findings: list[Finding]) -> dict[str, Issue]:
        """{issue label: ticket} for the findings that already have a ticket in this project, in any status.

        One search covers a chunk of findings, so a scan with hundreds of findings sends a few requests, not hundreds.
        When a finding has more than one ticket, the oldest one is the real one.
        """
        labels = sorted({issue_label(f) for f in findings})
        found: dict[str, Issue] = {}
        for start in range(0, len(labels), _SEARCH_CHUNK):
            chunk = labels[start : start + _SEARCH_CHUNK]
            quoted = ", ".join(jql_quote(label) for label in chunk)
            for issue in self._search(f"project = {self.project_key} AND labels in ({quoted})"):
                for label in chunk:
                    if label in issue.labels and (label not in found or issue.number < found[label].number):
                        found[label] = issue
        return found

    def open_tickets_of_branch(self, branch_label: str, tool_labels: list[str]) -> list[Issue]:
        """Open tickets that a scan of this branch by one of these tools made."""
        tools = ", ".join(jql_quote(t) for t in tool_labels)
        return list(
            self._search(
                f"project = {self.project_key} AND labels = {jql_quote(branch_label)} "
                f"AND labels in ({tools}) AND statusCategory != Done"
            )
        )

    def todo_ticket_keys(self, branch_label: str) -> list[str]:
        """The keys of the tickets of this branch that are still To Do, oldest first. Done and In Progress tickets are not listed."""
        issues = self._search(
            f"project = {self.project_key} AND labels = {jql_quote(branch_label)} AND statusCategory = \"To Do\""
        )
        return [issue.key for issue in sorted(issues, key=lambda i: i.number)]

    def oldest_with_label(self, label: str) -> Issue | None:
        issues = list(self._search(f"project = {self.project_key} AND labels = {jql_quote(label)}"))
        return min(issues, key=lambda i: i.number) if issues else None

    def transition(self, key: str, category: str) -> bool:
        """Moves a ticket to the first status of this category ("done" or "new"). Never hardcodes a status name,
        because workflows differ per project. False when the workflow has no such transition."""
        for t in self._request("GET", f"/rest/api/3/issue/{key}/transitions").get("transitions", []):
            if (t.get("to") or {}).get("statusCategory", {}).get("key") == category:
                self._request("POST", f"/rest/api/3/issue/{key}/transitions", body={"transition": {"id": t["id"]}})
                return True
        return False

    def add_comment(self, key: str, text: str) -> None:
        body = {"body": {"type": "doc", "version": 1, "content": [_code_block(_truncate(text))]}}
        self._request("POST", f"/rest/api/3/issue/{key}/comment", body=body)

    def change_labels(self, key: str, add: list[str] = (), remove: list[str] = ()) -> None:
        update = [{"add": label} for label in add] + [{"remove": label} for label in remove]
        self._request("PUT", f"/rest/api/3/issue/{key}", body={"update": {"labels": update}})

    def attach_png(self, key: str, filename: str, content: bytes) -> None:
        boundary = uuid.uuid4().hex
        head = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: image/png\r\n\r\n'
        body = head.encode() + content + f"\r\n--{boundary}--\r\n".encode()
        self._request(
            "POST",
            f"/rest/api/3/issue/{key}/attachments",
            raw_body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "X-Atlassian-Token": "no-check"},
        )

    def _active_sprint(self) -> int | None:
        if self._sprint_looked_up:
            return self._sprint_id
        self._sprint_looked_up = True
        try:
            boards = self._request("GET", "/rest/agile/1.0/board", {"projectKeyOrId": self.project_key}).get("values", [])
            if boards:
                sprints = self._request("GET", f"/rest/agile/1.0/board/{boards[0]['id']}/sprint", {"state": "active"})
                if sprints.get("values"):
                    self._sprint_id = sprints["values"][0]["id"]
        except JiraError as e:
            # A Kanban board answers 400 here. Either way new tickets stay in the backlog.
            log.warning(f"No active sprint found, new tickets stay in the backlog: {e}")
        return self._sprint_id

    def create_ticket(self, finding: Finding) -> str:
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": ticket_title(finding.repo_full_name, finding.component, finding.line, finding.title),
                "issuetype": {"name": "Bug"},
                "priority": {"name": SEVERITY_TO_PRIORITY[finding.severity]},
                "labels": ticket_labels(finding),
                "description": build_description(finding),
            }
        }
        key = self._request("POST", "/rest/api/3/issue", body=payload)["key"]
        # Sprint and link are bonuses. A failure here never undoes a ticket that exists.
        try:
            sprint = self._active_sprint()
            if sprint is not None:
                self._request("POST", f"/rest/agile/1.0/sprint/{sprint}/issue", body={"issues": [key]})
        except JiraError as e:
            log.warning(f"{key} was not added to the sprint: {e}")
        try:
            self._request(
                "POST",
                f"/rest/api/3/issue/{key}/remotelink",
                body={"object": {"url": finding.deep_link, "title": f"{finding.source_tool} finding"}},
            )
        except JiraError as e:
            log.warning(f"The link of {key} was not added: {e}")
        return key
