#!/usr/bin/env bash
set -euo pipefail

MANIFEST_PATH="${1:-requirements.txt}"

packguard scan manifest \
  --file "$MANIFEST_PATH" \
  --source pypi \
  --fail-on suspicious \
  --output reports/pip-install-guard.json

pip install -r "$MANIFEST_PATH"
