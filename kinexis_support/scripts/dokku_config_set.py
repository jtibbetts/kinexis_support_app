#!/usr/bin/env python3
"""
Push env vars from a managed env file to a Dokku app via SSH.

Uses `dokku config:import` via stdin to avoid shell-quoting issues
with special characters in values.

App name is derived from the env file path:
  ~/.config/openchannel/env.prod    -> openchannel
  ~/.config/openchannel/env.staging -> openchannel-staging
  ~/.config/openchannel/env.dev     -> refused (dev does not push to Dokku)

Examples:
  python dokku_config_set.py ~/.config/openchannel/env.prod --ssh dokku@dokku.kinexis.com
  python dokku_config_set.py --all-in ~/.config/openchannel --ssh dokku@dokku.kinexis.com
  python dokku_config_set.py ~/.config/openchannel/env.staging --ssh dokku@dokku.kinexis.com --app my-app
  python dokku_config_set.py ~/.config/openchannel/env.prod --ssh dokku@dokku.kinexis.com --no-restart
  python dokku_config_set.py --all-in ~/.config/openchannel --ssh dokku@dokku.kinexis.com --dry-run
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from kinexis_support.services.secrets_refresh.domain import (
    RefreshSecretsError,
    parse_env_body,
    parse_header,
)
from kinexis_support.services.secrets_refresh.fileio import read_lines


_ENV_TO_APP_SUFFIX: dict[str, str] = {
    "prod":       "",
    "production": "",
    "staging":    "-staging",
}

_DEV_ENVS = {"dev", "development"}


def derive_app_name(path: Path) -> str:
    project = path.parent.name
    parts = path.name.split(".", 1)
    if len(parts) < 2:
        raise ValueError(f"Cannot derive environment from filename: {path.name!r}")
    env = parts[1]
    if env in _DEV_ENVS:
        raise ValueError(f"{path.name} is a dev environment and should not be pushed to Dokku.")
    if env not in _ENV_TO_APP_SUFFIX:
        raise ValueError(
            f"Unknown environment {env!r} in {path.name}. "
            f"Expected one of: {', '.join(sorted(_ENV_TO_APP_SUFFIX))}"
        )
    return f"{project}{_ENV_TO_APP_SUFFIX[env]}"


def push_env(env_file: str, ssh: str, app: str | None, no_restart: bool, dry_run: bool) -> None:
    path = Path(env_file).expanduser().resolve()
    lines = read_lines(str(path))
    _, _start, end_idx = parse_header(lines)
    env = parse_env_body(lines, end_idx)

    app_name = app or derive_app_name(path)

    if dry_run:
        print(f"[dry-run] Would push {len(env)} vars from {path.name} to {app_name} via {ssh}")
        return

    env_content = "".join(f"{k}={v}\n" for k, v in sorted(env.items()))
    remote_cmd = f"dokku config:import {'--no-restart ' if no_restart else ''}{app_name}"
    cmd = ["ssh", ssh, remote_cmd]

    proc = subprocess.run(
        cmd,
        input=env_content,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"config:import failed for {app_name}.\n"
            f"STDERR:\n{proc.stderr.strip()}\n"
            f"STDOUT:\n{proc.stdout.strip()}"
        )

    if proc.stdout.strip():
        print(proc.stdout.strip())
    print(f"Pushed {len(env)} vars to {app_name}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Push env vars from a managed env file to a Dokku app via SSH."
    )

    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("env_file", nargs="?", help="Path to a single env file.")
    target.add_argument(
        "--all-in",
        metavar="DIRECTORY",
        help="Push all non-dev env.* files in the given directory.",
    )

    ap.add_argument(
        "--ssh",
        required=True,
        help="SSH target for the Dokku host, e.g. dokku@dokku.kinexis.com",
    )
    ap.add_argument(
        "--app",
        default=None,
        help="Override the Dokku app name (single file only).",
    )
    ap.add_argument(
        "--no-restart",
        action="store_true",
        help="Pass --no-restart to dokku config:import (skip app restart).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be pushed without executing.",
    )

    args = ap.parse_args()

    if args.app and args.all_in:
        print("ERROR: --app cannot be used with --all-in", file=sys.stderr)
        return 1

    if args.all_in:
        all_paths = sorted(Path(args.all_in).expanduser().glob("env.*"))
        files: list[str] = []
        for p in all_paths:
            env = p.name.split(".", 1)[1] if "." in p.name else ""
            if env in _DEV_ENVS:
                print(f"Skipping {p.name} (dev environment)")
                continue
            files.append(str(p))
        if not files:
            print(f"No pushable env.* files found in {args.all_in}", file=sys.stderr)
            return 1
    else:
        files = [args.env_file]

    errors: list[tuple[str, str]] = []
    for env_file in files:
        try:
            push_env(env_file, args.ssh, args.app, args.no_restart, args.dry_run)
        except (ValueError, RuntimeError, RefreshSecretsError) as e:
            errors.append((env_file, str(e)))

    if errors:
        for path, msg in errors:
            print(f"ERROR [{path}]: {msg}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
