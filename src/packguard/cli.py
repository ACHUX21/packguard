"""CLI for Packguard."""

from __future__ import annotations

import argparse

from packguard.config import load_config
from packguard.engine.pipeline import ScanPipeline
from packguard.errors import PackguardError
from packguard.logging import setup_logging
from packguard.reporting.console import render_console_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deterministic malicious-package screening for npm and PyPI artifacts"
    )
    parser.add_argument("--config", help="Path to JSON or YAML config file")
    parser.add_argument("--log-level", help="Override logging level")

    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan packages, lockfiles, archives, or manifests")
    scan_subparsers = scan_parser.add_subparsers(dest="scan_target", required=True)

    package_parser = scan_subparsers.add_parser("package", help="Scan a package from npm or PyPI")
    package_parser.add_argument("--source", choices=["npm", "pypi"], required=True)
    package_parser.add_argument("--name", required=True)
    package_parser.add_argument("--version")
    package_parser.add_argument("--output", default=None)
    package_parser.add_argument("--fail-on", choices=["clean", "suspicious", "malicious", "none"])

    manifest_parser = scan_subparsers.add_parser(
        "manifest",
        help="Scan dependencies from a manifest; npm package.json prefers a sibling package-lock.json when present",
    )
    manifest_parser.add_argument("--file", required=True, help="package.json or requirements.txt")
    manifest_parser.add_argument("--source", choices=["npm", "pypi"], required=True)
    manifest_parser.add_argument("--output", default=None)
    manifest_parser.add_argument("--fail-on", choices=["clean", "suspicious", "malicious", "none"])

    lockfile_parser = scan_subparsers.add_parser(
        "lockfile",
        help="Scan an exact npm package-lock.json with transitive dependency coverage",
    )
    lockfile_parser.add_argument("--file", required=True, help="Path to package-lock.json")
    lockfile_parser.add_argument("--source", choices=["npm"], required=True)
    lockfile_parser.add_argument("--output", default=None)
    lockfile_parser.add_argument("--fail-on", choices=["clean", "suspicious", "malicious", "none"])

    archive_parser = scan_subparsers.add_parser("archive", help="Scan a local wheel, sdist, or tarball")
    archive_parser.add_argument("--path", required=True)
    archive_parser.add_argument("--source", choices=["npm", "pypi"], required=True)
    archive_parser.add_argument("--name", required=True)
    archive_parser.add_argument("--version")
    archive_parser.add_argument("--output", default=None)
    archive_parser.add_argument("--fail-on", choices=["clean", "suspicious", "malicious", "none"])

    subparsers.add_parser("doctor", help="Print local configuration and feature status")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.log_level:
        config.log_level = args.log_level

    logger = setup_logging(config.log_level)
    pipeline = ScanPipeline(config, logger)

    if args.command == "doctor":
        print(_render_doctor(config, pipeline))
        return 0

    try:
        if args.scan_target == "package":
            from packguard.models import PackageCoordinate

            results = [
                pipeline.scan_package(
                    PackageCoordinate(
                        name=args.name,
                        source=args.source,
                        version=args.version,
                        requested_version=args.version,
                    )
                )
            ]
            output_path = args.output
            fail_on = args.fail_on
        elif args.scan_target == "manifest":
            results = pipeline.scan_manifest(args.file, args.source)
            output_path = args.output
            fail_on = args.fail_on
        elif args.scan_target == "lockfile":
            results = pipeline.scan_lockfile(args.file, args.source)
            output_path = args.output
            fail_on = args.fail_on
        else:
            results = [
                pipeline.scan_archive(
                    path=args.path,
                    source=args.source,
                    name=args.name,
                    version=args.version,
                )
            ]
            output_path = args.output
            fail_on = args.fail_on
    except (PackguardError, OSError, ValueError) as exc:
        parser.exit(status=2, message=f"packguard: error: {exc}\n")

    pipeline.write_report(results, output_path)
    print(render_console_summary(results))
    return _exit_code(results, fail_on or config.fail_on)


def _render_doctor(config, pipeline) -> str:
    threat_feed_info = pipeline.threat_feed.snapshot_info()
    popularity_info = pipeline.popularity.snapshot_info()
    ai_info = pipeline.explainer.metadata()
    return "\n".join(
        [
            "Packguard doctor",
            f"  log level: {config.log_level}",
            f"  output path: {config.output_path}",
            f"  offline mode: {config.offline_mode}",
            "  AI explainability: "
            f"{ai_info['status']} (provider={ai_info['provider']}, model={ai_info['model']})",
            f"  scanners: {', '.join(config.scanners)}",
            "  lockfile support: package-lock.json=yes, pnpm-lock.yaml=no",
            "  integrity validation: npm_sri=yes, npm_shasum=yes, pypi_sha256=yes",
            f"  popular packages: {popularity_info['path']} (entries={popularity_info['entry_count']}, updated_at={popularity_info['updated_at']})",
            f"  malicious feed: {threat_feed_info['path']} (entries={threat_feed_info['entry_count']}, updated_at={threat_feed_info['updated_at']})",
        ]
    )


def _exit_code(results, fail_on: str) -> int:
    if fail_on == "none":
        return 0

    severity_order = {"clean": 0, "suspicious": 1, "malicious": 2}
    threshold = severity_order[fail_on]
    worst = max(severity_order[result.verdict] for result in results)
    if fail_on == "clean":
        return 1 if worst > 0 else 0
    return 1 if worst >= threshold else 0
