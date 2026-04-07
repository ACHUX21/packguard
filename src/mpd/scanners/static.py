import os
import re
from mpd.utils.file_utils import read_lines

class StaticScanner:
    def scan(self, file_path: str) -> list:
        issues = []
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            # Check for obfuscated code patterns
            if re.search(r'eval\s*\(', content):
                issues.append("Contains eval() usage")
            if re.search(r'exec\s*\(', content):
                issues.append("Contains exec() usage")
            if re.search(r'os\.system\s*\(', content):
                issues.append("Contains os.system() usage")
            # Base64 encoded strings
            if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', content):
                issues.append("Contains large base64 string")
        except Exception as e:
            issues.append(f"Cannot read file: {e}")
        return issues
