"""Download and extract package artifacts."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib import parse, request

from packguard.errors import ExtractionError
from packguard.models import ExtractionResult, ResolvedPackage


TEXT_EXTENSIONS = {
    ".cjs",
    ".cfg",
    ".conf",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".mjs",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


class ArtifactExtractor:
    def extract(self, package: ResolvedPackage) -> ExtractionResult:
        workspace = Path(tempfile.mkdtemp(prefix="packguard-"))
        archive_path = workspace / (package.artifact_filename or "artifact")
        self._materialize_archive(package, archive_path)
        self._verify_integrity(package, archive_path)

        extract_root = workspace / "contents"
        extract_root.mkdir(parents=True, exist_ok=True)
        self._unpack_archive(archive_path, extract_root)
        return ExtractionResult(
            root_dir=workspace,
            files=self._list_candidate_files(extract_root),
            metadata_files=self._list_metadata_files(extract_root),
        )

    def cleanup(self, extraction: ExtractionResult) -> None:
        shutil.rmtree(extraction.root_dir, ignore_errors=True)

    def _materialize_archive(self, package: ResolvedPackage, destination: Path) -> None:
        source = package.artifact_path or package.artifact_url
        if not source:
            raise ExtractionError(f"No artifact path or URL available for '{package.coordinate.name}'")

        parsed = parse.urlparse(source)
        try:
            if parsed.scheme in {"", "file"}:
                source_path = parse.unquote(parsed.path) if parsed.scheme == "file" else source
                shutil.copyfile(source_path, destination)
            else:
                with request.urlopen(source, timeout=60) as response, destination.open("wb") as handle:
                    shutil.copyfileobj(response, handle)
        except Exception as exc:
            raise ExtractionError(
                f"Could not download artifact for '{package.coordinate.name}': {exc}"
            ) from exc

    def _verify_integrity(self, package: ResolvedPackage, archive_path: Path) -> None:
        if package.artifact_path and not package.artifact_url:
            package.integrity.setdefault("status", "not-applicable")
            package.integrity.setdefault("provider", "local")
            return

        value = package.integrity.get("value")
        kind = package.integrity.get("kind")
        if not value or not kind:
            package.integrity["status"] = "missing"
            return

        file_bytes = archive_path.read_bytes()
        if kind == "sri":
            algorithm, _, expected = value.partition("-")
            if not algorithm or not expected:
                raise ExtractionError(
                    f"Invalid SRI integrity metadata for '{package.coordinate.name}'"
                )

            digest = hashlib.new(algorithm, file_bytes).digest()
            actual = base64.b64encode(digest).decode("ascii")
            if actual != expected:
                package.integrity["status"] = "mismatch"
                raise ExtractionError(
                    f"Integrity mismatch for '{package.coordinate.name}' using {algorithm}"
                )
            package.integrity["status"] = "verified"
            package.integrity["verified_with"] = algorithm
            return

        if kind in hashlib.algorithms_available:
            actual = hashlib.new(kind, file_bytes).hexdigest()
            if actual != value:
                package.integrity["status"] = "mismatch"
                raise ExtractionError(
                    f"Integrity mismatch for '{package.coordinate.name}' using {kind}"
                )
            package.integrity["status"] = "verified"
            package.integrity["verified_with"] = kind
            return

        package.integrity["status"] = "unsupported"
        package.integrity["verified_with"] = kind

    def _unpack_archive(self, archive_path: Path, extract_root: Path) -> None:
        try:
            if archive_path.suffix in {".whl", ".zip"}:
                with zipfile.ZipFile(archive_path, "r") as archive:
                    self._safe_extract_zip(archive, extract_root)
            else:
                with tarfile.open(archive_path, "r:*") as archive:
                    self._safe_extract_tar(archive, extract_root)
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            raise ExtractionError(f"Could not extract '{archive_path.name}': {exc}") from exc

    def _list_candidate_files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {
                "package.json",
                "pyproject.toml",
                "setup.py",
                "setup.cfg",
            }:
                files.append(path)
        return sorted(files)

    def _list_metadata_files(self, root: Path) -> list[Path]:
        return sorted(
            [
                path
                for path in root.rglob("*")
                if path.is_file()
                and (
                    path.name == "package.json"
                    or path.name.endswith(".pth")
                    or path.name in {"pyproject.toml", "setup.py", "setup.cfg"}
                )
            ]
        )

    @staticmethod
    def _safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
        for member in archive.getmembers():
            target = destination / member.name
            if not ArtifactExtractor._is_within_directory(destination, target):
                raise ValueError(f"Blocked archive path traversal via '{member.name}'")
        archive.extractall(destination)

    @staticmethod
    def _safe_extract_zip(archive: zipfile.ZipFile, destination: Path) -> None:
        for name in archive.namelist():
            target = destination / name
            if not ArtifactExtractor._is_within_directory(destination, target):
                raise ValueError(f"Blocked archive path traversal via '{name}'")
        archive.extractall(destination)

    @staticmethod
    def _is_within_directory(directory: Path, target: Path) -> bool:
        try:
            target.resolve().relative_to(directory.resolve())
            return True
        except ValueError:
            return False
