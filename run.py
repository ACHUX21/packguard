#!/usr/bin/env python3
"""Convenience entrypoint for local development."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from packguard.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
