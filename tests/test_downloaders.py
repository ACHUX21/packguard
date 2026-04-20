import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from packguard.models import PackageCoordinate
from packguard.sources.npm import NpmSource
from packguard.sources.pypi import PyPISource


class DummyHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class DownloaderTestCase(unittest.TestCase):
    def test_npm_source_resolves_latest_version_and_tarball(self):
        payload = {
            "dist-tags": {"latest": "1.2.3"},
            "versions": {
                "1.2.3": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/react/-/react-1.2.3.tgz",
                        "integrity": "sha512-demo",
                    }
                }
            },
            "time": {"1.2.3": "2026-04-20T00:00:00+00:00"},
        }

        with mock.patch(
            "urllib.request.urlopen",
            return_value=DummyHTTPResponse(json.dumps(payload).encode("utf-8")),
        ):
            package = NpmSource().resolve(PackageCoordinate(name="react", source="npm"))

        self.assertEqual(package.coordinate.name, "react")
        self.assertEqual(package.coordinate.version, "1.2.3")
        self.assertEqual(package.coordinate.source, "npm")
        self.assertTrue(package.artifact_url.endswith("react-1.2.3.tgz"))
        self.assertEqual(package.artifact_filename, "react-1.2.3.tgz")
        self.assertEqual(package.integrity["status"], "pending")
        self.assertEqual(package.integrity["kind"], "sri")
        self.assertEqual(package.published_at, "2026-04-20T00:00:00+00:00")

    def test_pypi_source_prefers_sdist_artifact(self):
        payload = {
            "info": {"version": "2.1.0"},
            "urls": [
                {
                    "packagetype": "bdist_wheel",
                    "filename": "demo-2.1.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/demo-2.1.0.whl",
                    "digests": {"sha256": "wheelhash"},
                },
                {
                    "packagetype": "sdist",
                    "filename": "demo-2.1.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/demo-2.1.0.tar.gz",
                    "digests": {"sha256": "sdisthash"},
                },
            ],
        }

        with mock.patch(
            "urllib.request.urlopen",
            return_value=DummyHTTPResponse(json.dumps(payload).encode("utf-8")),
        ):
            package = PyPISource().resolve(PackageCoordinate(name="demo", source="pypi"))

        self.assertEqual(package.coordinate.name, "demo")
        self.assertEqual(package.coordinate.version, "2.1.0")
        self.assertEqual(package.coordinate.source, "pypi")
        self.assertTrue(package.artifact_url.endswith("demo-2.1.0.tar.gz"))
        self.assertEqual(package.artifact_filename, "demo-2.1.0.tar.gz")
        self.assertEqual(package.integrity["status"], "pending")
        self.assertEqual(package.integrity["kind"], "sha256")
        self.assertEqual(package.integrity["value"], "sdisthash")


if __name__ == "__main__":
    unittest.main()
