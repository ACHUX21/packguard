"""Static code and file heuristics."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from packguard.config import Config
from packguard.models import ExtractionResult, Finding, ResolvedPackage


CONTENT_RULES = [
    {
        "rule_id": "static.exec-eval",
        "pattern": re.compile(r"\b(eval|exec)\s*\("),
        "title": "Dynamic code execution",
        "summary": "Uses eval/exec style execution that can hide payloads.",
        "severity": "high",
        "confidence": "medium",
        "family": "static",
        "rationale": "Dynamic execution makes malicious behavior harder to inspect statically.",
        "tags": ["dynamic-execution"],
    },
    {
        "rule_id": "static.shell-spawn",
        "pattern": re.compile(r"(os\.system|subprocess\.(run|Popen)|child_process\.(exec|spawn))"),
        "title": "Spawns shell commands",
        "summary": "Launches shell commands directly from package code.",
        "severity": "high",
        "confidence": "medium",
        "family": "static",
        "rationale": "Package code should rarely spawn shells during install or import paths.",
        "tags": ["shell", "command-execution"],
    },
    {
        "rule_id": "static.network-and-exec",
        "pattern": re.compile(
            r"(curl|wget|Invoke-WebRequest|urllib\.request|requests\.(get|post)|fetch\()"
        ),
        "title": "Network-capable execution path",
        "summary": "Contains network fetch primitives commonly used in download-and-exec chains.",
        "severity": "medium",
        "confidence": "medium",
        "family": "static",
        "rationale": "Install-time or startup code that fetches remote content can stage second-phase payloads.",
        "tags": ["network", "loader"],
    },
    {
        "rule_id": "static.credential-harvest",
        "pattern": re.compile(
            r"(AWS_ACCESS_KEY_ID|GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|SSH_AUTH_SOCK|\.npmrc|id_rsa)"
        ),
        "title": "Credential access indicators",
        "summary": "References developer secrets or sensitive credential material.",
        "severity": "high",
        "confidence": "medium",
        "family": "static",
        "rationale": "Targeting developer credentials is a common supply-chain malware objective.",
        "tags": ["credentials", "exfiltration"],
    },
    {
        "rule_id": "static.download-exec-chain",
        "pattern": re.compile(r"(curl|wget).*(\||&&).*(bash|sh|python|node)|powershell.+Download"),
        "title": "Download-and-execute chain",
        "summary": "Looks like a staged loader that fetches and immediately executes remote content.",
        "severity": "high",
        "confidence": "high",
        "family": "static",
        "rationale": "Download-and-exec behavior is a high-signal pattern for malware loaders.",
        "tags": ["loader", "network", "command-execution"],
    },
    {
        "rule_id": "static.sensitive-path-access",
        "pattern": re.compile(r"(\.ssh/|\.npmrc|\.kube/config|\.aws/credentials|/etc/passwd|/etc/shadow)"),
        "title": "Sensitive filesystem targeting",
        "summary": "References filesystem locations commonly used for developer credentials or host reconnaissance.",
        "severity": "high",
        "confidence": "medium",
        "family": "static",
        "rationale": "Malicious packages frequently target local secrets and developer workstation state.",
        "tags": ["filesystem", "credentials"],
    },
    {
        "rule_id": "static.concatenated-loader",
        "pattern": re.compile(r"(?:['\"](?:cu|wg|po|ba)['\"]\s*\+\s*['\"][^'\"]+['\"])|(?:\+\s*['\"](?:sh|bash|curl|wget)['\"])"),
        "title": "String-built loader",
        "summary": "Builds suspicious command strings dynamically to evade direct string matching.",
        "severity": "medium",
        "confidence": "medium",
        "family": "static",
        "rationale": "String concatenation is a simple but common evasion tactic for install-time loaders.",
        "tags": ["evasion", "loader"],
    },
]

OBFUSCATION_PATTERN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
HEX_BLOB_PATTERN = re.compile(r"(?:0x)?[0-9a-fA-F]{120,}")
SUSPICIOUS_PYTHON_CALLS = {"eval", "exec", "__import__", "compile"}
PYTHON_NETWORK_CALLS = {
    "requests.get",
    "requests.post",
    "urllib.request.urlopen",
    "http.client.HTTPConnection",
    "socket.create_connection",
}
SENSITIVE_PATH_STRINGS = (".ssh", ".npmrc", ".kube/config", ".aws/credentials")


class StaticScanner:
    def __init__(self, config: Config):
        self.config = config

    def scan(self, package: ResolvedPackage, extraction: ExtractionResult) -> list[Finding]:
        findings: list[Finding] = []
        for path in extraction.files:
            content = self._read_text(path)
            if content is None:
                continue
            relative_path = str(path.relative_to(extraction.root_dir))
            phase = self._phase_for_path(path)
            findings.extend(self._scan_content(relative_path, phase, content))
            if path.suffix.lower() == ".py":
                findings.extend(self._scan_python_ast(relative_path, phase, content))
        findings.extend(self._scan_binary_signals(extraction))
        return findings

    def _scan_content(self, location: str, phase: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in CONTENT_RULES:
            if not rule["pattern"].search(content):
                continue
            findings.append(
                Finding(
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    summary=rule["summary"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    family=rule["family"],
                    phase=phase,
                    rationale=rule["rationale"],
                    detector="static",
                    location=location,
                    evidence=[self._sample_match(rule["pattern"], content)],
                    tags=list(rule["tags"]),
                )
            )

        if self._looks_obfuscated(content):
            findings.append(
                Finding(
                    rule_id="static.obfuscated-blob",
                    title="Large encoded payload",
                    summary="Contains a large encoded or hexadecimal blob that may hide a payload.",
                    severity="medium",
                    confidence="medium",
                    family="static",
                    phase=phase,
                    rationale="Large encoded blobs are often used to hide second-stage payloads or shellcode.",
                    detector="static",
                    location=location,
                    evidence=["Encoded blob length exceeded heuristic threshold"],
                    tags=["obfuscation"],
                )
            )
        return findings

    def _scan_python_ast(self, location: str, phase: str, content: str) -> list[Finding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        call_names: set[str] = set()
        string_literals: list[str] = []
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self._call_name(node.func)
                if name:
                    call_names.add(name)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                string_literals.append(node.value)

        if SUSPICIOUS_PYTHON_CALLS.intersection(call_names):
            findings.append(
                Finding(
                    rule_id="static.python-ast-dynamic-exec",
                    title="Python dynamic execution primitive",
                    summary="Python AST contains direct dynamic execution calls.",
                    severity="high",
                    confidence="high",
                    family="static",
                    phase=phase,
                    rationale="AST-level detection is harder to evade than simple text matching.",
                    detector="static",
                    location=location,
                    evidence=sorted(SUSPICIOUS_PYTHON_CALLS.intersection(call_names)),
                    tags=["python", "dynamic-execution"],
                )
            )

        if PYTHON_NETWORK_CALLS.intersection(call_names) and any(
            sensitive in value for sensitive in SENSITIVE_PATH_STRINGS for value in string_literals
        ):
            findings.append(
                Finding(
                    rule_id="static.python-secret-exfil-intent",
                    title="Python secret exfiltration path",
                    summary="Python code combines network access with references to sensitive local files.",
                    severity="high",
                    confidence="high",
                    family="static",
                    phase=phase,
                    rationale="The combination of network calls and secret file targeting is a strong malicious signal.",
                    detector="static",
                    location=location,
                    evidence=["network calls plus sensitive path strings detected"],
                    tags=["python", "credentials", "exfiltration"],
                )
            )

        return findings

    def _scan_binary_signals(self, extraction: ExtractionResult) -> list[Finding]:
        findings: list[Finding] = []
        for path in extraction.root_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in {".node", ".so", ".dll", ".dylib", ".exe"}:
                findings.append(
                    Finding(
                        rule_id="static.native-binary",
                        title="Native binary in package",
                        summary="Native code increases audit complexity and can hide malicious behavior.",
                        severity="medium",
                        confidence="medium",
                        family="static",
                        phase=self._phase_for_path(path),
                        rationale="Native payloads bypass many source-only review workflows.",
                        detector="static",
                        location=str(path.relative_to(extraction.root_dir)),
                        evidence=["Binary extension detected"],
                        tags=["native-code"],
                    )
                )
        return findings

    def _read_text(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")[: self.config.max_file_bytes]
        except OSError:
            return None

    @staticmethod
    def _phase_for_path(path: Path) -> str:
        name = path.name.lower()
        if name.endswith(".pth"):
            return "startup"
        if name in {"package.json", "setup.py", "setup.cfg", "pyproject.toml"}:
            return "install"
        if "scripts" in path.parts:
            return "build"
        return "runtime"

    @staticmethod
    def _sample_match(pattern: re.Pattern[str], content: str) -> str:
        match = pattern.search(content)
        return match.group(0)[:120] if match else "pattern matched"

    @staticmethod
    def _looks_obfuscated(content: str) -> bool:
        for candidate in OBFUSCATION_PATTERN.findall(content):
            if any(character.isalpha() for character in candidate):
                return True
        return bool(HEX_BLOB_PATTERN.search(content))

    @staticmethod
    def _call_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            current: ast.AST | None = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        return None
