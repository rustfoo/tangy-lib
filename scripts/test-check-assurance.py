"""Regression tests for platform-specific evidence requirements (no external tools)."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
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

    def test_python_evidence_uses_actual_outcomes(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        source = scripts / "test-installer.py"
        source.write_text(textwrap.dedent('''\
            import unittest
            class InstallerTests(unittest.TestCase):
                # Assures: TOOLS-TEST-001
                def test_pass(self): pass
                # Assures: TOOLS-TEST-001
                def test_fail(self): self.fail("regression")
                # Assures: TOOLS-TEST-001
                def test_error(self): raise ValueError("regression")
                # Assures: TOOLS-TEST-001
                @unittest.skip("unavailable")
                def test_skip(self): pass
                # Assures: TOOLS-TEST-001
                def test_subtest(self):
                    with self.subTest(case=1): self.fail("regression")
                # Assures: TOOLS-TEST-001
                def test_subtest_skip(self):
                    with self.subTest(case=1): self.skipTest("unavailable")
                # Assures: TOOLS-TEST-001
                def test_nested_subtest_skip(self):
                    with self.subTest(outer=1):
                        with self.subTest(inner=1): self.skipTest("unavailable")
                # Assures: TOOLS-TEST-001
                def test_partial_subtest_skip(self):
                    with self.subTest(case=1): self.assertTrue(True)
                    with self.subTest(case=2): self.skipTest("unavailable")
                # Assures: TOOLS-TEST-001
                @unittest.expectedFailure
                def test_expected_failure(self): self.fail("regression")
                # Assures: TOOLS-TEST-001
                @unittest.expectedFailure
                def test_unexpected_success(self): pass
            '''))
        report = self.root / "installer.xml"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("run-python-tests.py")),
             str(source), "--junit", str(report)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        checker.errors.clear()
        with patch.object(checker, "root", self.root):
            tags = checker.tagged_tests("example")
            results = checker.junit_results("installer", report)
        binary = "test-installer.InstallerTests"
        self.assertEqual(len([key for key in tags if key[0] == binary]), 10)
        expected = {"pass": "passed", "fail": "failed", "error": "failed",
                    "skip": "skipped", "subtest": "failed", "subtest_skip": "skipped",
                    "nested_subtest_skip": "skipped", "partial_subtest_skip": "skipped",
                    "expected_failure": "skipped",
                    "unexpected_success": "failed"}
        self.assertEqual(len(results), len(expected))
        for name, outcome in expected.items():
            self.assertEqual(results[binary, f"test_{name}"], outcome)
        self.assertEqual(checker.errors, [])

        (self.root / "assurance/assertions.toml").write_text(
            '[[assertion]]\nid = "TOOLS-TEST-001"\nstatement = "test"\n'
            'min_evidence = 2\nrequired_reports = ["installer"]\n')
        args = ["check-assurance.py", "--junit", f"installer={report}"]
        checker.errors.clear()
        with patch.object(checker, "root", self.root), patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checker.main(), 1)
        self.assertTrue(any("installer has 1 of 2" in error for error in checker.errors))

    def test_python_tags_must_be_attached_to_test_methods(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "test-invalid.py").write_text(
            '# Assures: KEY-TEST-001\ndef helper(): pass\n'
            'example = """\n# Assures: NOT-A-TAG-001\n"""\n')
        checker.errors.clear()
        with patch.object(checker, "root", self.root):
            self.assertEqual(checker.python_tagged_tests(), {})
        self.assertEqual(len(checker.errors), 1)
        self.assertIn("not attached to a unittest test method", checker.errors[0])

    def test_python_assertion_is_supported_only_when_the_test_is_reported(self):
        (self.root / "src/lib.rs").unlink()
        scripts = self.root / "scripts"
        scripts.mkdir()
        source = scripts / "test-installer.py"
        source.write_text(
            'import unittest\nclass InstallerTests(unittest.TestCase):\n'
            '    # Assures: TOOLS-TEST-001\n    def test_safe(self): pass\n')
        (self.root / "assurance/assertions.toml").write_text(
            '[[assertion]]\nid = "TOOLS-TEST-001"\nstatement = "test"\n'
            'min_evidence = 1\nrequired_reports = ["installer"]\n')
        report = self.root / "installer.xml"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("run-python-tests.py")),
             str(source), "--junit", str(report)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = ["check-assurance.py", "--junit", f"installer={report}"]
        for expected in [0, 1]:
            checker.errors.clear()
            with patch.object(checker, "root", self.root), patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(checker.main(), expected)
            report.write_text('<testsuite><testcase classname="unrelated" name="other"/></testsuite>')
        self.assertTrue(any("tagged but absent" in error for error in checker.errors))

    def test_python_fixture_errors_are_reported(self):
        source = self.root / "test-broken-fixture.py"
        source.write_text(
            'import unittest\nclass BrokenTests(unittest.TestCase):\n'
            '    @classmethod\n    def setUpClass(cls): raise ValueError("broken fixture")\n'
            '    def test_unreached(self): pass\n')
        report = self.root / "fixture.xml"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("run-python-tests.py")),
             str(source), "--junit", str(report)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        results = checker.junit_results("installer", report)
        self.assertEqual(list(results.values()), ["failed"])


if __name__ == "__main__":
    unittest.main()
