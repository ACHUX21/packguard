"""Popular package lookup used for typosquat detection."""

from __future__ import annotations

from pathlib import Path


class PopularityIndex:
    def __init__(self, path: str):
        self.path = Path(path)
        self.packages = self._load_packages()

    def snapshot_info(self) -> dict:
        if not self.path.exists():
            return {"path": str(self.path), "updated_at": None, "entry_count": 0}
        stat = self.path.stat()
        return {
            "path": str(self.path),
            "updated_at": stat.st_mtime,
            "entry_count": len(self.packages),
        }

    def _load_packages(self) -> list[str]:
        if not self.path.exists():
            return []
        return [
            line.strip()
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
