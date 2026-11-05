import tempfile
import unittest
from pathlib import Path

from gozu_scan import llm, snippet
from gozu_scan.models import Finding, Severity


def make(rule="eval-detected", line=3, component="app.py", sensitive=False) -> Finding:
    return Finding(
        key="k",
        title="Use of eval()",
        severity=Severity.HIGH,
        component=component,
        line=line,
        message="Do not use eval.",
        finding_type="vulnerability",
        deep_link="https://example.invalid",
        source_tool="semgrep",
        rule_key=rule,
        sensitive=sensitive,
    )


class Snippet(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        Path(self.dir.name, "app.py").write_text("\n".join(f"line {i}" for i in range(1, 60)))

    def test_the_window_is_the_flagged_line_and_its_context(self):
        text, start = snippet.read_window(self.dir.name, "app.py", 30)

        self.assertEqual(start, 15)
        self.assertEqual(text.splitlines()[0], "line 15")
        self.assertEqual(len(text.splitlines()), 31)

    def test_a_path_outside_the_checkout_is_never_read(self):
        outside = Path(self.dir.name).parent / "outside.txt"
        outside.write_text("secret")
        self.addCleanup(outside.unlink)

        self.assertIsNone(snippet.read_window(self.dir.name, "../outside.txt", 1))
        self.assertIsNone(snippet.read_window(self.dir.name, "/etc/passwd", 1))

    def test_a_missing_file_gives_no_window(self):
        self.assertIsNone(snippet.read_window(self.dir.name, "gone.py", 1))

    def test_a_finding_that_may_hold_a_secret_gets_no_snippet(self):
        for finding in (make(sensitive=True), make(rule="generic.secrets.detected-generic-api-key")):
            with self.subTest(finding.rule_key):
                snippet.attach_window(finding, self.dir.name)
                self.assertIsNone(finding.code_snippet)

    def test_a_normal_finding_gets_a_snippet_and_a_package_finding_gets_none(self):
        normal, package = make(), make(line=None)

        snippet.attach_window(normal, self.dir.name)
        snippet.attach_window(package, self.dir.name)

        self.assertIn("line 3", normal.code_snippet)
        self.assertIsNone(package.code_snippet)


class Llm(unittest.TestCase):
    def test_the_prompt_holds_the_code_of_a_normal_finding(self):
        finding = make()
        finding.code_snippet = "eval(user_input)"

        self.assertIn("eval(user_input)", llm.build_prompt(finding))

    def test_the_prompt_never_holds_the_code_of_a_secret(self):
        finding = make(sensitive=True)
        finding.code_snippet = "KEY=AKIAIOSFODNN7EXAMPLE"

        prompt = llm.build_prompt(finding)

        self.assertNotIn("AKIA", prompt)
        self.assertIn("withheld", prompt)

    def test_only_critical_and_high_are_explained(self):
        self.assertEqual(set(llm.ELIGIBLE), {Severity.CRITICAL, Severity.HIGH})


if __name__ == "__main__":
    unittest.main()
