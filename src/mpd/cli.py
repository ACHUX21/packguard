#!/usr/bin/env python3
"""Command-line interface for MPD."""
import argparse
from mpd import config, logger
from mpd.core.detector import Detector

def main():
    parser = argparse.ArgumentParser(description="Malicious Package Detector")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    args = parser.parse_args()

    cfg = config.load(args.config)
    log = logger.setup(args.log_level)
    detector = Detector(cfg, log)
    detector.run()

if __name__ == "__main__":
    main()
