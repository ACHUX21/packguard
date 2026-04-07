"""Logger setup."""
import logging

def setup(level="INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    return logging.getLogger("mpd")
