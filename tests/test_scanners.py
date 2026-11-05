import json
import unittest

from gozu_scan import semgrep, trivy
from gozu_scan.models import ScanError, Severity

TRIVY_OUTPUT = json.dumps(
    {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2018-1000656",
                        "PkgName": "flask",
                        "InstalledVersion": "0.12",
                        "FixedVersion": "",
                        "Title": "flask: denial of service",
                        "Severity": "UNKNOWN",
                    }
                ],
            },
            {
                "Target": "config/.env",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Title": "AWS Access Key ID",
                        "Severity": "CRITICAL",
                        "StartLine": 3,
                        "Match": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
                        "Code": {"Lines": [{"Content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"}]},
                    }
                ],
            },
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "Image user should not be root",
                        "Severity": "HIGH",
                        "Resolution": "Add a USER instruction.",
                        "CauseMetadata": {"StartLine": 1},
                    }
                ],
            },
            {
                "Target": ".github/workflows/ci.yml",
                "Misconfigurations": [{"ID": "AVD-X", "Title": "ignored", "Severity": "LOW"}],
            },
        ]
    }
)


class TrivyParsing(unittest.TestCase):
    def setUp(self):
        self.findings = trivy.parse(TRIVY_OUTPUT)

    def test_each_kind_of_result_becomes_a_finding_and_ignored_paths_are_dropped(self):
        self.assertEqual([f.rule_key for f in self.findings], ["CVE-2018-1000656", "aws-access-key-id", "DS002"])

    def test_a_vulnerability_is_a_package_finding_with_no_line(self):
        vuln = self.findings[0]

        self.assertIsNone(vuln.line)
        self.assertEqual((vuln.package_name, vuln.installed_version), ("flask", "0.12"))
        self.assertIsNone(vuln.fixed_version)
        self.assertEqual(vuln.title, "CVE-2018-1000656 | flask | denial of service")
        self.assertEqual(vuln.severity, Severity.MEDIUM)

    def test_a_secret_never_reaches_the_ticket_text(self):
        secret = self.findings[1]

        self.assertEqual(secret.line, 3)
        self.assertNotIn("AKIA", json.dumps(secret.__dict__, default=str))

    def test_a_misconfiguration_carries_its_line_and_resolution(self):
        misconf = self.findings[2]

        self.assertEqual((misconf.line, misconf.severity), (1, Severity.HIGH))
        self.assertEqual(misconf.how_to_fix, "Add a USER instruction.")

    def test_unreadable_output_is_a_scan_error(self):
        with self.assertRaises(ScanError):
            trivy.parse("not json")


class SemgrepParsing(unittest.TestCase):
    def test_a_result_becomes_a_finding(self):
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.eval",
                        "path": "app.py",
                        "start": {"line": 5},
                        "extra": {"severity": "ERROR", "message": "Use of eval()"},
                    },
                    {"check_id": "x", "path": ".github/workflows/a.yml", "start": {"line": 1}, "extra": {}},
                ]
            }
        )

        findings = semgrep.parse(output)

        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].line, findings[0].severity), (5, Severity.HIGH))
        self.assertEqual(findings[0].rule_key, "python.lang.security.eval")

    def test_no_output_means_no_findings(self):
        self.assertEqual(semgrep.parse(""), [])


if __name__ == "__main__":
    unittest.main()
