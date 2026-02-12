#!/usr/bin/env python3
"""
Export Dokku config vars for a given app into two files:

1) <app>.env               -> exact KEY=VALUE pairs as exported by Dokku
2) <app>.env.template      -> KEY="" (blank value placeholder)

By default this runs `dokku config:export --format env <app>` locally (i.e., on the Dokku host).
Optionally, run against a remote Dokku host via SSH.

Examples:
  # On the Dokku host:
  python dokku_env_export.py openchannel

  # Remote Dokku host (runs dokku command over ssh):
  python dokku_env_export.py openchannel --ssh dokku@dokku2.kinexis.com

  # Custom output directory:
  python dokku_env_export.py openchannel -o ./exports

Notes:
- Output (1) contains secrets in plaintext. Treat it like a secrets file.
- Parsing is designed for `--format env` output (KEY=VALUE per line).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple


ENV_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def run_dokku_config_export(app: str, ssh: str | None) -> str:
    """
    Runs `dokku config:export --format env <app>` either locally or via ssh and returns stdout.
    """
    base_cmd = ["dokku", "config:export", "--format", "env", app]

    if ssh:
        # e.g. ssh dokku@host dokku config:export --format env app
        cmd = ["ssh", ssh, *base_cmd]
    else:
        cmd = base_cmd

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "Dokku export failed.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Exit code: {proc.returncode}\n"
            f"STDERR:\n{proc.stderr.strip()}\n"
            f"STDOUT:\n{proc.stdout.strip()}\n"
        )

    return proc.stdout


def parse_env_lines(text: str) -> List[Tuple[str, str]]:
    """
    Parses lines of the form KEY=VALUE. Keeps order.
    Skips blank lines and comments.
    """
    items: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m = ENV_LINE_RE.match(line)
        if not m:
            # If Dokku ever emits something unexpected, keep it visible
            raise ValueError(f"Unrecognized env line: {raw!r}")
        key, val = m.group(1), m.group(2)
        items.append((key, val))
    return items


def write_exact_env_file(path: Path, items: List[Tuple[str, str]]) -> None:
    """
    Writes KEY=VALUE lines exactly as parsed (no re-quoting).
    """
    content = "\n".join(f"{k}={v}" for k, v in items) + "\n"
    path.write_text(content, encoding="utf-8")


def write_template_env_file(path: Path, items: List[Tuple[str, str]]) -> None:
    """
    Writes KEY="" placeholder lines (blank values).
    """
    content = "\n".join(f'{k}=""' for k, _ in items) + "\n"
    path.write_text(content, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Export Dokku env vars to .env and .env.template files.")
    ap.add_argument("app", help="Dokku app name (e.g., openchannel)")
    ap.add_argument(
        "--ssh",
        help="Optional SSH target for remote Dokku host, e.g. dokku@dokku2.example.com",
        default=None,
    )
    ap.add_argument(
        "-o",
        "--outdir",
        help="Output directory (default: current directory)",
        default=".",
    )
    ap.add_argument(
        "--prefix",
        help="Optional filename prefix (default: app name). Files become: <prefix>.env and <prefix>.env.template",
        default=None,
    )

    args = ap.parse_args()

    outdir = Path(args.outdir).expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    prefix = args.prefix or args.app
    exact_path = outdir / f"{prefix}.env"
    template_path = outdir / f"{prefix}.env.template"

    raw = run_dokku_config_export(args.app, args.ssh)
    items = parse_env_lines(raw)

    write_exact_env_file(exact_path, items)
    write_template_env_file(template_path, items)

    print(f"Wrote exact env file:      {exact_path}")
    print(f"Wrote template env file:   {template_path}")
    print(f"Exported {len(items)} variables.")
    print("WARNING: The exact env file contains secrets; store it securely.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
