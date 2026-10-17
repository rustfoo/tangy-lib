"""Regression tests for platform-specific evidence requirements (no external tools)."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("check_assurance", Path(__file__).with_name("check-assurance.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "assurance").mkdir()
        (self.root / "Cargo.toml").write_text('[package]\nname = "example"\n')
        (self.root / "src/lib.rs").write_text(''.join(
            f'/// Assures: KEY-TEST-001\n#[test]\nfn test_{i}() {{}}\n' for i in range(2)))
        (self.root / "assurance/assertions.toml").write_text(
            '[[assertion]]\nid = "KEY-TEST-001"\nstatement = "test"\n'
            'min_evidence = 2\nrequired_reports = ["linux", "windows"]\n')

    def tearDown(self):
        self.temp.cleanup()

    def check(self, reports):
        args = ["check-assurance.py"]
        for label, cases in reports.items():
            path = self.root / f"{label}.xml"
            path.write_text('<testsuite>' + ''.join(
                f'<testcase classname="example" name="test_{i}">{outcome}</testcase>'
                for i, outcome in cases.items()) + '</testsuite>')
            args.extend(["--junit", f"{label}={path}"])
        checker.errors.clear()
        with patch.object(checker, "root", self.root), patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = checker.main()
        return result, checker.errors.copy()

    def test_each_required_report_must_meet_the_minimum(self):
        self.assertEqual(self.check({"linux": {0: "", 1: ""}, "windows": {0: "", 1: ""}})[0], 0)
        result, errors = self.check({"linux": {0: "", 1: ""}, "windows": {0: ""}})
        self.assertEqual(result, 1)
        self.assertTrue(any("windows has 1 of 2" in error for error in errors))

    def test_platform_evidence_cannot_be_pooled(self):
        result, errors = self.check({"linux": {0: ""}, "windows": {1: ""}})
        self.assertEqual(result, 1)
        self.assertTrue(any("linux has 1 of 2" in error for error in errors))
        self.assertTrue(any("windows has 1 of 2" in error for error in errors))

    def test_missing_required_report_is_an_error(self):
        result, errors = self.check({"linux": {0: "", 1: ""}})
        self.assertEqual(result, 1)
        self.assertTrue(any("required report windows is missing" in error for error in errors))

    def test_skipped_and_failed_tests_do_not_support_an_assertion(self):
        for outcome in ['<skipped/>', '<failure/>']:
            result, errors = self.check({"linux": {0: "", 1: outcome}, "windows": {0: "", 1: ""}})
            self.assertEqual(result, 1)
            self.assertTrue(any("linux has 1 of 2" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
