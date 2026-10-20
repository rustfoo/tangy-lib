"""Run a Python unittest file and record actual outcomes as JUnit evidence."""

import argparse
import importlib.util
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True


class JUnitResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.suite = ET.Element("testsuite")
        self.cases = {}

    def startTest(self, test):
        super().startTest(test)
        self.case(test)

    def case(self, test):
        if test not in self.cases:
            self.cases[test] = ET.SubElement(
                self.suite, "testcase",
                classname=f"{test.__class__.__module__}.{test.__class__.__qualname__}",
                name=getattr(test, "_testMethodName", test.id()),
            )
        return self.cases[test]

    def addFailure(self, test, err):
        super().addFailure(test, err)
        ET.SubElement(self.case(test), "failure").text = self._exc_info_to_string(err, test)

    def addError(self, test, err):
        super().addError(test, err)
        ET.SubElement(self.case(test), "error").text = self._exc_info_to_string(err, test)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        ET.SubElement(self.case(test), "skipped", message=reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        ET.SubElement(self.case(test), "skipped", message="expected failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        ET.SubElement(self.case(test), "failure", message="unexpected success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            outcome = "failure" if issubclass(err[0], test.failureException) else "error"
            ET.SubElement(self.case(test), outcome).text = self._exc_info_to_string(err, subtest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("test_file", type=Path)
    parser.add_argument("--junit", required=True, type=Path)
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location(args.test_file.stem, args.test_file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    tests = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(resultclass=JUnitResult, verbosity=2).run(tests)
    args.junit.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(result.suite).write(args.junit, encoding="utf-8", xml_declaration=True)
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__ == "__main__":
    sys.exit(main())
