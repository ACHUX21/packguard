import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from base64 import b64encode
from hashlib import sha512

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.extractors.archive import ArtifactExtractor
from packguard.errors import ExtractionError
from packguard.models import PackageCoordinate, ResolvedPackage


class ExtractorTestCase(unittest.TestCase):
    def test_extractor_downloads_and_extracts_tarball(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, "demo.tgz")
            source_file = os.path.join(tmpdir, "index.js")
            with open(source_file, "w", encoding="utf-8") as handle:
                handle.write("console.log('hello')")

            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(source_file, arcname="package/index.js")

            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", version="1.0.0", source="npm"),
                artifact_path=archive_path,
                artifact_filename="demo.tgz",
            )

            extraction = ArtifactExtractor().extract(package)

        self.assertEqual(len(extraction.files), 1)
        self.assertTrue(str(extraction.files[0]).endswith("index.js"))

    def test_extractor_downloads_and_extracts_wheel(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, "demo.whl")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("demo/__init__.py", "__version__ = '1.0.0'")

            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", version="1.0.0", source="pypi"),
                artifact_path=archive_path,
                artifact_filename="demo.whl",
            )

            extraction = ArtifactExtractor().extract(package)

        self.assertEqual(len(extraction.files), 1)
        self.assertTrue(str(extraction.files[0]).endswith("__init__.py"))

    def test_extractor_verifies_integrity_for_registry_style_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, "demo.tgz")
            source_file = os.path.join(tmpdir, "index.js")
            with open(source_file, "w", encoding="utf-8") as handle:
                handle.write("console.log('hello')")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(source_file, arcname="package/index.js")

            with open(archive_path, "rb") as handle:
                digest = sha512(handle.read()).digest()
            sri = f"sha512-{b64encode(digest).decode('ascii')}"

            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", version="1.0.0", source="npm"),
                artifact_url=archive_path,
                artifact_filename="demo.tgz",
                integrity={"status": "pending", "kind": "sri", "value": sri},
            )

            extraction = ArtifactExtractor().extract(package)

        self.assertEqual(package.integrity["status"], "verified")
        self.assertEqual(len(extraction.files), 1)

    def test_extractor_rejects_integrity_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, "demo.tgz")
            source_file = os.path.join(tmpdir, "index.js")
            with open(source_file, "w", encoding="utf-8") as handle:
                handle.write("console.log('hello')")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(source_file, arcname="package/index.js")

            package = ResolvedPackage(
                coordinate=PackageCoordinate(name="demo", version="1.0.0", source="npm"),
                artifact_url=archive_path,
                artifact_filename="demo.tgz",
                integrity={"status": "pending", "kind": "sha256", "value": "deadbeef"},
            )

            with self.assertRaises(ExtractionError):
                ArtifactExtractor().extract(package)


if __name__ == "__main__":
    unittest.main()
