# Packguard

Status: alpha. Ready for evaluation and early feedback, not yet positioned as production-complete supply chain protection.

Packguard is a deterministic malware-oriented package screener for open-source dependencies. It focuses on the gap that classic SCA tools miss: malicious packages, install-time execution, typosquats, credential-harvesting loaders, and suspicious package behavior before code lands on a developer machine or CI runner.

It is designed for teams that want local artifact scanning, deterministic rule-based verdicts, exact npm lockfile coverage where available, and optional AI-generated explanations from Ollama or common hosted providers.

## Why Packguard Exists

Most dependency scanners are excellent at known CVEs and weak at brand-new malicious packages. That gap matters because modern package attacks usually:

- execute at install time through `postinstall`, `preinstall`, `setup.py`, or `.pth` files
- exfiltrate developer or CI secrets before application code even runs
- hide inside transitive dependencies or typo/namespace attacks
- disappear before vulnerability databases catch up

Packguard is built for that problem, not for generic vulnerability management.

## What It Does Today

- Scans exact npm dependencies from `package-lock.json`, including transitives
- Scans npm and PyPI packages directly from the registry
- Scans local archives offline (`.tgz`, `.tar.gz`, `.whl`, `.zip`)
- Scans manifests like `package.json` and `requirements.txt`
- Detects install-time scripts and startup hooks
- Flags shell execution, credential access, download-and-exec primitives, sensitive path targeting, and large encoded payloads
- Detects typosquat and simple scope-confusion attacks
- Matches packages against a local malicious package feed snapshot
- Verifies artifact integrity when registry metadata provides hashes or SRI values
- Produces JSON reports suitable for CI and policy enforcement
- Optionally uses Ollama, OpenAI, Anthropic, Gemini, Groq, OpenRouter, or xAI to summarize findings

## What It Is Not

- It is not a replacement for CVE scanners like `pip-audit`, `npm audit`, Snyk, or Dependabot
- It is not a full dynamic sandbox
- It does not claim perfect malware detection
- AI providers do not set the verdict; they only explain findings
- PyPI manifest scanning is direct-only today unless you provide a local artifact
- `pnpm-lock.yaml` is not implemented yet

## Installation

### Bootstrap Script

```bash
./setup.sh
source .venv/bin/activate
```

Install the optional Ollama client too:

```bash
./setup.sh --ollama
```

### Standard

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### With Ollama Explainability

```bash
pip install -e .[dev,ollama]
```

### With Hosted AI Providers

No extra Python dependency is required for OpenAI, Anthropic, Gemini, Groq, OpenRouter, or xAI. Packguard uses direct HTTPS calls for those providers.

### With YAML Config Support

```bash
pip install -e .[dev,yaml]
```

### Docker

```bash
docker build -t packguard:local .
docker run --rm packguard:local doctor
docker run --rm -v "$PWD:/workspace" -w /workspace packguard:local scan lockfile --file package-lock.json --source npm
```

Or with Compose:

```bash
docker compose run --rm packguard doctor
```

## Quick Start

### Scan a package from npm

```bash
packguard scan package --source npm --name left-pad
```

### Scan a package from PyPI

```bash
packguard scan package --source pypi --name requests --version 2.32.3
```

### Scan a local archive offline

```bash
packguard scan archive --path ./dist/demo-1.0.0.whl --source pypi --name demo --version 1.0.0
```

### Scan every dependency in a manifest

```bash
packguard scan manifest --file package.json --source npm --fail-on suspicious
packguard scan manifest --file requirements.txt --source pypi --fail-on suspicious
```

### Scan an exact npm lockfile

```bash
packguard scan lockfile --file package-lock.json --source npm --fail-on suspicious
```

### Check local setup

```bash
packguard doctor
```

## CLI Design

```text
packguard scan package  --source <npm|pypi> --name <package> [--version X] [--output report.json] [--fail-on <clean|suspicious|malicious|none>]
packguard scan archive  --path <artifact> --source <npm|pypi> --name <package> [--version X] [--output report.json] [--fail-on ...]
packguard scan manifest --file <package.json|requirements.txt> --source <npm|pypi> [--output report.json] [--fail-on ...]
packguard scan lockfile --file <package-lock.json> --source npm [--output report.json] [--fail-on ...]
packguard doctor
```

## Detection Pipeline

### 1. Threat feed match

Compares exact `name + version + ecosystem` against a local malicious package feed snapshot.

### 2. Exact dependency coverage when available

Uses `package-lock.json` to scan pinned npm versions and track parent/dependency depth. Manifest-only scans are explicitly reported as `direct-only`.

### 3. Typosquat and namespace analysis

Checks package names against a local popularity index and flags edit-distance collisions and untrusted scopes.

### 4. Install-time behavior analysis

Looks for:

- npm `preinstall`, `install`, `postinstall`, `prepare`
- Python `.pth` startup files
- Python build/install hooks and suspicious entry points
- environment-aware install logic
- network-and-shell behavior inside install scripts

### 5. Static content analysis

Looks for:

- eval/exec style dynamic execution
- `child_process`, `subprocess`, `os.system`
- network fetch + execution paths
- credential access indicators
- sensitive filesystem targeting
- simple string-built loader evasion
- large encoded or obfuscated blobs
- native binary payloads

### 6. Integrity validation

When registry or lockfile metadata provides an integrity value, Packguard verifies the artifact before unpacking it. Missing or unverifiable integrity is reported in the result.

### 7. Optional explainability

If enabled, Packguard asks the configured provider for a short explanation. Supported providers are:

- `ollama`
- `openai`
- `anthropic`
- `gemini`
- `groq`
- `openrouter`
- `xai`

The verdict still comes from deterministic scoring.

## Output

Packguard writes a JSON report by default to `reports/packguard-report.json`.

Example:

```json
{
  "generated_at": "2026-04-20T00:00:00+00:00",
  "total_packages": 1,
  "malicious_count": 0,
  "suspicious_count": 1
}
```

## Configuration

Default config template lives at [config/packguard.default.json](config/packguard.default.json).

Key settings:

- `scanners`: choose which scanners run
- `risk_thresholds`: tune verdict boundaries
- `typosquat_distance`: tighten or loosen name matching
- `trusted_scopes`: suppress expected scoped package names
- `private_namespaces`: reserve internal package names for namespace-confusion checks
- `use_ai`: enable optional AI summaries
- `ai_provider`: choose `ollama`, `openai`, `anthropic`, `gemini`, `groq`, `openrouter`, or `xai`
- provider credentials and model names can be set in config or via environment variables such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, and `XAI_API_KEY`

Example:

```bash
export PACKGUARD_USE_AI=true
export PACKGUARD_AI_PROVIDER=openai
export OPENAI_API_KEY=...
packguard scan archive --path ./dist/demo-1.0.0.tgz --source npm --name demo
```

## CI / Hooks

### GitHub Actions

CI is configured in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### Pre-commit

```bash
pre-commit install
```

### Safe install wrappers

- [examples/hooks/npm-safe-install.sh](examples/hooks/npm-safe-install.sh)
- [examples/hooks/pip-safe-install.sh](examples/hooks/pip-safe-install.sh)

These wrappers gate installs on Packguard scan results before `npm install` or `pip install`.

## Project Structure

```text
config/
data/intel/
examples/hooks/
src/packguard/
  ai/
  engine/
  extractors/
  intel/
  reporting/
  scanners/
  sources/
tests/
```

## Development

```bash
pip install -e .[dev]
python -m pytest -q
ruff check src tests
python -m build --sdist --wheel
python run.py doctor
```

## Release

Use [docs/release-checklist.md](docs/release-checklist.md) for the first public alpha and later tagged releases.

## Roadmap

- transitive dependency graph resolution and risk propagation
- sandboxed install-time execution with syscall/network capture
- SBOM generation and diffing
- `pnpm-lock.yaml` and workspace-native scanning
- richer offline threat-intel bundles and signed update snapshots

## License

MIT
