"""Check that every assertion in assurance/assertions.toml is supported by passing tests.

Tests claim assertions with a doc comment directly above them:

    /// Assures: KEY-PERM-001, KEY-STORE-001
    #[test]
    fn ...

Results come from nextest JUnit reports, so only tests that actually ran and
passed count as evidence. Usage:

    check-assurance.py --junit linux=target/nextest/ci/junit.xml [--junit LABEL=PATH ...]
                       [--out evidence.json]
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parent.parent
TAG = re.compile(r"^\s*///\s*Assures:\s*(.+?)\s*$")
FN = re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)")
ID = re.compile(r"^[A-Z]+(?:-[A-Z]+)*-\d{3}$")
errors = []


def binary_id(path, crate):
    """The nextest binary ID for tests defined in a source file."""
    rel = path.relative_to(root)
    return crate if rel.parts[0] == "src" else f"{crate}::{rel.stem}"


def tagged_tests(crate):
    """Map (binary, fn name) to the assertion IDs its tag claims."""
    tags = {}
    for path in sorted([*root.glob("src/**/*.rs"), *root.glob("tests/*.rs")]):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines):
            match = TAG.match(line)
            if not match:
                continue
            where = f"{path.relative_to(root)}:{number + 1}"
            ids = [i.strip() for i in match.group(1).split(",")]
            is_test, name = False, None
            for following in lines[number + 1:]:
                stripped = following.strip()
                if stripped == "#[test]":
                    is_test = True
                elif stripped.startswith(("///", "#[")) or not stripped:
                    continue
                else:
                    name = FN.match(following) and FN.match(following).group(1)
                    break
            if not (is_test and name):
                errors.append(f"{where}: Assures tag is not attached to a #[test] fn")
                continue
            key = (binary_id(path, crate), name)
            if key in tags:
                errors.append(f"{where}: duplicate test name {name} in {key[0]}")
            tags[key] = ids
    return tags


def junit_results(label, path):
    """Map (binary, test name) to passed/failed/skipped for one report."""
    results = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.find("skipped") is not None:
            outcome = "skipped"
        elif case.find("failure") is not None or case.find("error") is not None:
            outcome = "failed"
        else:
            outcome = "passed"
        results[(case.get("classname"), case.get("name"))] = outcome
    if not results:
        errors.append(f"{label}: {path} contains no test cases")
    return results


def run_matches(results, binary, name):
    """Outcomes for a test, whose JUnit name may carry a module path."""
    return [
        outcome for (suite, case), outcome in results.items()
        if suite == binary and (case == name or case.endswith(f"::{name}"))
    ]


def command(*args):
    try:
        return subprocess.check_output(args, cwd=root, text=True, timeout=30).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", action="append", required=True, metavar="LABEL=PATH")
    parser.add_argument("--registry", type=Path, default=root / "assurance" / "assertions.toml")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    crate = tomllib.loads((root / "Cargo.toml").read_text())["package"]["name"]
    assertions = tomllib.loads(args.registry.read_text())["assertion"]
    known = {}
    for assertion in assertions:
        if not ID.match(assertion["id"]):
            errors.append(f"registry: malformed assertion ID {assertion['id']}")
        if assertion["id"] in known:
            errors.append(f"registry: duplicate assertion ID {assertion['id']}")
        known[assertion["id"]] = assertion

    runs = {}
    for spec in args.junit:
        label, _, path = spec.partition("=")
        if not path:
            parser.error(f"--junit expects LABEL=PATH, got {spec}")
        runs[label] = junit_results(label, Path(path))

    tags = tagged_tests(crate)
    evidence = {id: [] for id in known}
    for (binary, name), ids in sorted(tags.items()):
        outcomes = {label: run_matches(results, binary, name) for label, results in runs.items()}
        ran = {label: found for label, found in outcomes.items() if found}
        if not ran:
            errors.append(f"{binary}::{name} is tagged but absent from every report")
        if any(len(found) > 1 for found in ran.values()):
            errors.append(f"{binary}::{name} matches several reported tests")
        if any("failed" in found for found in ran.values()):
            errors.append(f"{binary}::{name} failed")
        record = {
            "test": f"{binary}::{name}",
            "runs": {label: found[0] for label, found in ran.items()},
        }
        record["passed"] = bool(ran) and all(o == "passed" for o in record["runs"].values())
        for id in ids:
            if id in evidence:
                evidence[id].append(record)
            else:
                errors.append(f"{binary}::{name} claims unknown assertion {id}")

    report = []
    for id, assertion in known.items():
        passing = sum(record["passed"] for record in evidence[id])
        supported = passing >= assertion["min_evidence"]
        if not supported:
            errors.append(f"{id}: {passing} of {assertion['min_evidence']} required passing tests")
        report.append({**assertion, "passing": passing, "supported": supported,
                       "evidence": evidence[id]})
        print(f"{'ok ' if supported else 'GAP'} {id:<16} {passing}/{assertion['min_evidence']}"
              f"  {assertion['statement']}")

    reported = {key for results in runs.values() for key in results}
    untagged = [f"{suite}::{case}" for suite, case in sorted(reported)
                if not any(suite == b and (case == n or case.endswith(f"::{n}")) for b, n in tags)]
    if untagged:
        print(f"\n{len(untagged)} reported tests support no assertion:")
        print("".join(f"  {name}\n" for name in untagged), end="")

    if args.out:
        lock = root / "Cargo.lock"
        args.out.write_text(json.dumps({
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "commit": command("git", "rev-parse", "HEAD"),
            "dirty": bool(command("git", "status", "--porcelain")),
            "cargo_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None,
            "reports": {spec.partition("=")[0]: spec.partition("=")[2] for spec in args.junit},
            "supported": not errors,
            "errors": errors,
            "assertions": report,
            "untagged_tests": untagged,
        }, indent=2) + "\n")

    if errors:
        print("\nAssurance check failed:", *errors, sep="\n  ", file=sys.stderr)
        return 1
    print(f"\nAll {len(known)} assertions are supported by passing tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
