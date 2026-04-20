#!/usr/bin/env bash
set -euo pipefail

MANIFEST_PATH="${1:-package.json}"

packguard scan manifest \
  --file "$MANIFEST_PATH" \
  --source npm \
  --fail-on suspicious \
  --output reports/npm-install-guard.json

npm install
