from __future__ import annotations

import json
import re
import subprocess
from typing import Dict, List, Protocol

from .domain import RefreshSecretsError


class OpRunner(Protocol):
    def run(self, cmd: List[str]) -> str: ...


class SubprocessOpRunner:
    def run(self, cmd: List[str]) -> str:
        try:
            p = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return p.stdout
        except subprocess.CalledProcessError as e:
            raise RefreshSecretsError(
                f"Command failed: {' '.join(cmd)}\n\nSTDERR:\n{e.stderr.strip()}"
            ) from e


class OpClient:
    """
    Minimal adapter around the `op` CLI.
    """

    def __init__(self, runner: OpRunner | None = None) -> None:
        self._runner = runner or SubprocessOpRunner()

    def item_get_json(self, vault: str, item: str) -> dict:
        out = self._runner.run(
            ["op", "item", "get", item, "--vault", vault, "--format", "json"]
        )
        try:
            return json.loads(out)
        except json.JSONDecodeError as e:
            raise RefreshSecretsError(f"Failed to parse JSON for item {item}: {e}") from e


def fields_to_env(item_json: dict) -> Dict[str, str]:
    """
    Convert 1Password item fields into env vars.

    Uses:
      - field['label'] as env var key
      - field['value'] as value (stringified)

    Skips fields without label/value and rejects invalid env keys.
    """
    env: Dict[str, str] = {}
    fields = item_json.get("fields", []) or []
    for f in fields:
        label = f.get("label")
        value = f.get("value")
        if not label or value is None:
            continue
        if not isinstance(label, str):
            continue

            # Skip structured values
        if isinstance(value, (dict, list)):
            continue

        key = label.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise RefreshSecretsError(
                f"Invalid env var name from 1Password field label: {key!r}"
            )

        env[key] = str(value)

    return env


def fetch_env_from_items(op: OpClient, vault: str, items: List[str]) -> Dict[str, str]:
    """
    Merge env vars from all items. Collision policy: later items override earlier ones.
    """
    merged: Dict[str, str] = {}
    for item in items:
        item_json = op.item_get_json(vault, item)
        item_env = fields_to_env(item_json)
        for k, v in item_env.items():
            merged[k] = v
    return merged
