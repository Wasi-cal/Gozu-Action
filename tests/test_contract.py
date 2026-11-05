"""The golden tickets of the Gozu ticket contract. The same file is in gozu, Gozurion and veil."""

import json
import unittest
from pathlib import Path

from gozu_scan.contract import SEVERITY_TO_PRIORITY, ticket_labels, ticket_title
from gozu_scan.jira import build_description, build_details
from gozu_scan.models import Finding, Severity

GOLDEN = json.loads((Path(__file__).parent / "contract" / "golden_tickets.json").read_text())


def make_finding(spec: dict, **changes) -> Finding:
    values = dict(
        key=f"{spec['source']}:1",
        title=spec["title"],
        severity=Severity[spec["severity"]],
        component=spec["component"],
        line=spec["line"],
        message="The scanner message.",
        finding_type=spec["type"],
        deep_link="https://example.invalid/finding/1",
        source_tool=spec["source"],
        repo_full_name=spec["repo"],
        branch=spec["branch"],
        commit_sha=spec["commit"],
        rule_key=spec["rule"],
        package_name=spec.get("package"),
        installed_version=spec.get("installed_version"),
        fixed_version=spec.get("fixed_version"),
    )
    values.update(changes)
    return Finding(**values)


class GoldenTickets(unittest.TestCase):
    def test_every_case_follows_the_contract(self):
        for case in GOLDEN["cases"]:
            with self.subTest(case["name"]):
                finding = make_finding(case["finding"])
                expected = case["expected"]

                title = ticket_title(finding.repo_full_name, finding.component, finding.line, finding.title)
                self.assertEqual(title, expected["title"])
                self.assertLessEqual(len(title), 120)
                self.assertEqual(ticket_labels(finding), expected["labels"])
                self.assertEqual(build_details(finding), expected["details"])
                self.assertEqual(SEVERITY_TO_PRIORITY[finding.severity], expected["priority"])

    def test_the_same_finding_on_two_branches_gets_the_same_issue_label(self):
        spec = GOLDEN["cases"][0]["finding"]

        first = ticket_labels(make_finding(spec, branch="main"))
        second = ticket_labels(make_finding(spec, branch="feature/other"))

        self.assertEqual(first[0], second[0])
        self.assertNotEqual(first[2], second[2])

    def test_the_description_has_the_details_under_a_heading(self):
        description = build_description(make_finding(GOLDEN["cases"][0]["finding"]))

        headings = [n["content"][0]["text"] for n in description["content"] if n["type"] == "heading"]
        self.assertIn("Details", headings)


if __name__ == "__main__":
    unittest.main()
