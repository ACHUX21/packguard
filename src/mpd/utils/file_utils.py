import os
import json

def read_lines(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def write_json(filepath: str, data: dict):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
