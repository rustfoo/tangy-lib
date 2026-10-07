"""Exercise installer prefix safety without downloading or running package tools."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
script = Path(__file__).with_name("prepare-interop-prefix.py")
spec = importlib.util.spec_from_file_location("interop_prefix", script)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class PrefixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tangy-prefix-test-", dir="/tmp")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    # Assures: INTEROP-PREFIX-001
    def test_creation_is_private_even_with_a_permissive_umask(self):
        prefix = self.root / "new-parent" / "prefix"
        result = subprocess.run(
            [sys.executable, str(script), str(prefix)], umask=0,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(prefix))
        for path in [prefix.parent, prefix, *(prefix / name for name in ["cache", "state", "log", "packages", "root"])]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    # Assures: INTEROP-PREFIX-001
    def test_safe_existing_installation_is_reusable(self):
        prefix = self.root / "prefix"
        prefix.mkdir(mode=0o755)
        (prefix / "env.sh").write_text("# trusted activation\n")
        self.assertEqual(helper.prepare_prefix(prefix), prefix)
        self.assertEqual(prefix.stat().st_mode & 0o777, 0o700)
        self.assertEqual(helper.prepare_prefix(prefix), prefix)

    # Assures: INTEROP-PREFIX-001
    def test_symlinked_prefix_and_parent_are_rejected_without_touching_target(self):
        target = self.root / "target"
        target.mkdir()
        (target / "sentinel").write_text("unchanged")
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        for path in [alias, alias / "prefix"]:
            with self.subTest(path=path), self.assertRaises(OSError):
                helper.prepare_prefix(path)
        self.assertEqual(list(target.iterdir()), [target / "sentinel"])

    # Assures: INTEROP-PREFIX-001
    def test_group_or_world_writable_prefixes_are_rejected_without_chmod(self):
        prefix = self.root / "prefix"
        prefix.mkdir()
        for mode in [0o777, 0o770, 0o707]:
            prefix.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                helper.prepare_prefix(prefix)
            self.assertEqual(prefix.stat().st_mode & 0o777, mode)

    # Assures: INTEROP-PREFIX-001
    def test_writable_nonsticky_parent_is_rejected(self):
        parent = self.root / "shared"
        parent.mkdir()
        parent.chmod(0o777)
        with self.assertRaises(ValueError):
            helper.prepare_prefix(parent / "prefix")
        self.assertFalse((parent / "prefix").exists())

    # Assures: INTEROP-PREFIX-001
    def test_sticky_shared_parent_is_allowed(self):
        parent = self.root / "shared"
        parent.mkdir()
        parent.chmod(0o1777)
        prefix = parent / "prefix"
        self.assertEqual(helper.prepare_prefix(prefix), prefix)
        self.assertEqual(prefix.stat().st_mode & 0o777, 0o700)

    # Assures: INTEROP-PREFIX-001
    def test_foreign_owned_prefix_is_rejected(self):
        # The prefix is directly below root-owned /tmp, so the ownership check
        # applies to this prefix rather than an intermediate test directory.
        with patch.object(helper.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                helper.prepare_prefix(self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    # Assures: INTEROP-PREFIX-001
    def test_unsafe_existing_contents_are_rejected(self):
        prefix = self.root / "prefix"
        prefix.mkdir()
        unsafe = prefix / "env.sh"
        unsafe.write_text("untrusted activation")
        unsafe.chmod(0o666)
        with self.assertRaises(ValueError):
            helper.prepare_prefix(prefix)
        unsafe.unlink()
        outside = self.root / "outside"
        outside.write_text("unchanged")
        unsafe.symlink_to(outside)
        with self.assertRaises(ValueError):
            helper.prepare_prefix(prefix)
        self.assertEqual(outside.read_text(), "unchanged")

    # Assures: INTEROP-PREFIX-001
    def test_external_package_links_and_symlinked_work_directories_are_rejected(self):
        prefix = self.root / "prefix"
        prefix.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        link = prefix / "library.so"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            helper.prepare_prefix(prefix)
        link.unlink()
        (prefix / "inside").mkdir()
        (prefix / "cache").symlink_to(prefix / "inside", target_is_directory=True)
        with self.assertRaises(OSError):
            helper.prepare_prefix(prefix)

    # Assures: INTEROP-PREFIX-001
    def test_contained_package_library_symlinks_are_supported(self):
        prefix = self.root / "prefix"
        prefix.mkdir()
        library = prefix / "libjose.so.0.0.0"
        library.write_text("library")
        (prefix / "libjose.so.0").symlink_to(library.name)
        helper.prepare_prefix(prefix)

    # Assures: INTEROP-PREFIX-001
    @unittest.skipIf(os.getuid() == 0, "root can read directories regardless of their mode")
    def test_unreadable_existing_contents_are_rejected(self):
        prefix = self.root / "prefix"
        prefix.mkdir()
        unreadable = prefix / "unreadable"
        unreadable.mkdir()
        unreadable.chmod(0)
        try:
            with self.assertRaises(PermissionError):
                helper.prepare_prefix(prefix)
        finally:
            unreadable.chmod(0o700)

    # Assures: INTEROP-PREFIX-001
    def test_installer_refuses_unsafe_prefix_before_executing_tools(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        marker = self.root / "tool-executed"
        for name in ["dnf", "rpm", "rpm2cpio", "cpio", "curl", "jq", "timeout"]:
            tool = bin_dir / name
            tool.write_text('#!/bin/sh\nprintf executed > "$TOOL_MARKER"\nexit 1\n')
            tool.chmod(0o700)
        target = self.root / "target"
        target.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        result = subprocess.run(
            ["bash", str(script.with_name("install-interop-tools.sh")), str(alias)],
            env={**os.environ, "PATH": f'{bin_dir}:{os.environ["PATH"]}', "TOOL_MARKER": str(marker)},
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsafe interop prefix", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(list(target.iterdir()), [])

    # Assures: INTEROP-PACKAGES-001
    def test_installer_extracts_only_packages_from_the_successful_download(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        stub = f"#!{sys.executable}\n" + textwrap.dedent('''\
            import os
            from pathlib import Path
            import sys

            tool = Path(sys.argv[0]).name
            if tool == "timeout":
                os.execvp(sys.argv[2], sys.argv[2:])
            elif tool == "rpm" and sys.argv[1] == "--eval":
                print("x86_64" if sys.argv[2] == "%{_arch}" else "42")
            elif tool == "dnf":
                destination = Path(next(arg.split("=", 1)[1] for arg in sys.argv
                                        if arg.startswith("--destdir=")))
                fail = os.environ["FAIL_PRIMARY"] == "1" and "--repo=fedora" in sys.argv
                release = "9" if fail else "10"
                (destination / f"jose-1-{release}.x86_64.rpm").write_text("package")
                sys.exit(1 if fail else 0)
            elif tool == "rpm2cpio":
                print(Path(sys.argv[1]).name)
            elif tool == "cpio":
                with open(os.environ["EXTRACTED_PACKAGES"], "a") as output:
                    output.write(sys.stdin.read())
            ''')
        for name in ["dnf", "rpm", "rpm2cpio", "cpio", "curl", "jq", "timeout", "jose", "clevis"]:
            tool = bin_dir / name
            tool.write_text(stub)
            tool.chmod(0o700)
        for fail_primary in [False, True]:
            with self.subTest(fail_primary=fail_primary):
                prefix = self.root / f"prefix-{fail_primary}"
                helper.prepare_prefix(prefix)
                stale = prefix / "packages" / "jose-1-9.x86_64.rpm"
                stale.write_text("old package")
                extracted = self.root / f"extracted-{fail_primary}"
                result = subprocess.run(
                    ["bash", str(script.with_name("install-interop-tools.sh")), str(prefix)],
                    env={**os.environ, "PATH": f'{bin_dir}:{os.environ["PATH"]}',
                         "FAIL_PRIMARY": str(int(fail_primary)), "EXTRACTED_PACKAGES": str(extracted)},
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(extracted.read_text().splitlines(), ["jose-1-10.x86_64.rpm"])


if __name__ == "__main__":
    unittest.main()
