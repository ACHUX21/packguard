# Packguard Release Checklist

Target: `v0.2.0-alpha`

## Before tagging

- Verify `python -m unittest discover -s tests -v` passes
- Verify `ruff check src tests` passes
- Verify `python -m build --sdist --wheel` succeeds
- Verify a clean wheel install works:
  - `python -m venv /tmp/packguard-wheel`
  - `/tmp/packguard-wheel/bin/pip install dist/*.whl`
  - `/tmp/packguard-wheel/bin/python -m packguard doctor`
- Verify Docker build and runtime smoke test work:
  - `docker build -t packguard:alpha .`
  - `docker run --rm packguard:alpha doctor`
- Review README claims for accuracy against current capabilities
- Confirm `LICENSE` is present and matches package metadata
- Confirm bundled intel snapshots are present in the wheel

## Release notes should say

- Alpha release
- Deterministic malicious-package screening, not full SCA
- npm `package-lock.json` transitive support
- PyPI manifest support is direct-only
- AI providers are optional explainability only

## After tagging

- Create GitHub release `v0.2.0-alpha`
- Attach wheel and sdist artifacts if desired
- Include known limitations and roadmap in the release notes
