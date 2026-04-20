#!/usr/bin/env bash

set -euo pipefail

VENV_PATH=".venv"
INSTALL_DEV=1
INSTALL_YAML=1
INSTALL_OLLAMA=0
RUN_DOCTOR=1

usage() {
  cat <<'EOF'
Packguard setup

Usage:
  ./setup.sh [options]

Options:
  --venv-path PATH   Virtual environment path to create or reuse (default: .venv)
  --no-dev           Skip development dependencies
  --no-yaml          Skip YAML config support dependency
  --ollama           Install the optional Ollama Python client
  --no-doctor        Skip the post-install `packguard doctor` smoke check
  --help             Show this help text

Examples:
  ./setup.sh
  ./setup.sh --ollama
  ./setup.sh --venv-path /tmp/packguard-venv --no-dev

Notes:
  - Hosted AI providers like OpenAI, Anthropic, Gemini, Groq, OpenRouter, and xAI
    do not need an extra Python package.
  - Ollama support does require the optional `ollama` extra.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv-path)
      if [[ $# -lt 2 ]]; then
        echo "error: --venv-path requires a value" >&2
        exit 2
      fi
      VENV_PATH="$2"
      shift 2
      ;;
    --no-dev)
      INSTALL_DEV=0
      shift
      ;;
    --no-yaml)
      INSTALL_YAML=0
      shift
      ;;
    --ollama)
      INSTALL_OLLAMA=1
      shift
      ;;
    --no-doctor)
      RUN_DOCTOR=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac
done

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "error: Python 3.11+ is required but no python executable was found" >&2
  exit 1
fi

PYTHON_VERSION="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.major)')"
PYTHON_MINOR="$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.minor)')"

if [[ "$PYTHON_MAJOR" -lt 3 || ( "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 11 ) ]]; then
  echo "error: Packguard requires Python 3.11+ but found $PYTHON_VERSION" >&2
  exit 1
fi

echo "Using Python $PYTHON_VERSION from $(command -v "$PYTHON_BIN")"

if [[ ! -d "$VENV_PATH" ]]; then
  echo "Creating virtual environment at $VENV_PATH"
  "$PYTHON_BIN" -m venv "$VENV_PATH"
else
  echo "Reusing existing virtual environment at $VENV_PATH"
fi

VENV_PYTHON="$VENV_PATH/bin/python"
VENV_PIP="$VENV_PATH/bin/pip"

if [[ ! -x "$VENV_PYTHON" || ! -x "$VENV_PIP" ]]; then
  echo "error: virtual environment at $VENV_PATH is missing python or pip" >&2
  exit 1
fi

echo "Upgrading pip inside $VENV_PATH"
"$VENV_PYTHON" -m pip install --upgrade pip

declare -a EXTRAS=()
if [[ "$INSTALL_DEV" -eq 1 ]]; then
  EXTRAS+=("dev")
fi
if [[ "$INSTALL_YAML" -eq 1 ]]; then
  EXTRAS+=("yaml")
fi
if [[ "$INSTALL_OLLAMA" -eq 1 ]]; then
  EXTRAS+=("ollama")
fi

PACKAGE_SPEC="."
if [[ ${#EXTRAS[@]} -gt 0 ]]; then
  PACKAGE_SPEC=".[${EXTRAS[*]}]"
  PACKAGE_SPEC="${PACKAGE_SPEC// /,}"
fi

echo "Installing Packguard with spec $PACKAGE_SPEC"
"$VENV_PIP" install -e "$PACKAGE_SPEC"

if [[ "$RUN_DOCTOR" -eq 1 ]]; then
  echo "Running Packguard doctor"
  "$VENV_PATH/bin/packguard" doctor
fi

cat <<EOF

Packguard setup complete.

Activate the environment:
  source "$VENV_PATH/bin/activate"

Common next steps:
  packguard doctor
  packguard scan lockfile --file package-lock.json --source npm
  packguard scan archive --path ./dist/demo-1.0.0.tgz --source npm --name demo
EOF
