from __future__ import annotations

import os
from typing import List

from .domain import RefreshSecretsError


def read_lines(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()
    except FileNotFoundError as e:
        raise RefreshSecretsError(f"File not found: {path}") from e
    except OSError as e:
        raise RefreshSecretsError(f"Failed to read file: {path} ({e})") from e


def atomic_write_lines(path: str, lines: List[str]) -> None:
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(lines)
        os.replace(tmp_path, path)
    except OSError as e:
        raise RefreshSecretsError(f"Failed to write file: {path} ({e})") from e
