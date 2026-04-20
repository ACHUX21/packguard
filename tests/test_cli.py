import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.cli import _exit_code, build_parser
from packguard.models import PackageCoordinate, ResolvedPackage, ScanResult


class CLITestCase(unittest.TestCase):
    def test_parse_package_scan_command(self):
        parser = build_parser()
        args = parser.parse_args(
            ["scan", "package", "--source", "npm", "--name", "react", "--version", "18.3.1"]
        )

        self.assertEqual(args.command, "scan")
        self.assertEqual(args.scan_target, "package")
        self.assertEqual(args.source, "npm")
        self.assertEqual(args.name, "react")
        self.assertEqual(args.version, "18.3.1")

    def test_parse_manifest_scan_command(self):
        parser = build_parser()
        args = parser.parse_args(
            ["scan", "manifest", "--file", "requirements.txt", "--source", "pypi"]
        )

        self.assertEqual(args.scan_target, "manifest")
        self.assertEqual(args.file, "requirements.txt")
        self.assertEqual(args.source, "pypi")

    def test_parse_lockfile_scan_command(self):
        parser = build_parser()
        args = parser.parse_args(
            ["scan", "lockfile", "--file", "package-lock.json", "--source", "npm"]
        )

        self.assertEqual(args.scan_target, "lockfile")
        self.assertEqual(args.file, "package-lock.json")
        self.assertEqual(args.source, "npm")

    def test_exit_code_fails_when_policy_threshold_is_met(self):
        suspicious = ScanResult(
            package=ResolvedPackage(
                coordinate=PackageCoordinate(name="reaact", source="npm", version="1.0.0")
            ),
            findings=[],
            risk_score=42,
            verdict="suspicious",
        )

        self.assertEqual(_exit_code([suspicious], "suspicious"), 1)
        self.assertEqual(_exit_code([suspicious], "malicious"), 0)
        self.assertEqual(_exit_code([suspicious], "clean"), 1)


if __name__ == "__main__":
    unittest.main()
