import os
from jellyfish import levenshtein_distance
from mpd.utils.file_utils import read_lines

class TyposquatScanner:
    def __init__(self, popular_packages_path: str):
        self.popular = set(read_lines(popular_packages_path))

    def scan(self, file_path: str) -> list:
        issues = []
        base_name = os.path.basename(os.path.dirname(file_path))
        for popular in self.popular:
            if base_name.lower() != popular.lower():
                dist = levenshtein_distance(base_name.lower(), popular.lower())
                if 0 < dist <= 2:
                    issues.append(f"Possible typosquat of '{popular}' (distance: {dist})")
        return issues
