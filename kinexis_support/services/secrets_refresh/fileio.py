from __future__ import annotations

import os
from typing import List

from .domain import RefreshSecretsError

_SKELETON = """\
# @secrets:
#   vault:
#   items:
#   digest_alg: hmac-sha256
#   digest:
#   updated_at:
# @endsecrets
"""


def read_lines(path: str) -> List[str]:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(_SKELETON)
        raise RefreshSecretsError(
            f"Created {path} with a skeleton @secrets header — "
            "fill in vault and items, then run refresh again."
        )
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()
    except OSError as e:
        raise RefreshSecretsError(f"Failed to read file: {path} ({e})") from e


def atomic_write_lines(path: str, lines: List[str]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(lines)
        os.replace(tmp_path, path)
    except OSError as e:
        raise RefreshSecretsError(f"Failed to write file: {path} ({e})") from e
