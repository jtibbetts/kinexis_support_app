from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .domain import RefreshSecretsError
from .service import refresh_env_file


def _env_files_in(directory: str) -> list[Path]:
    return sorted(Path(directory).glob("env.*"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()

    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("env_file", nargs="?", help="Path to a single .env file to refresh.")
    target.add_argument(
        "--all-in",
        metavar="DIRECTORY",
        help="Refresh all env.* files in the given directory.",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="Verify existing digest matches current env contents before refreshing.",
    )
    ap.add_argument(
        "--no-verify-missing",
        action="store_true",
        help="If digest is missing, do not fail verification (treat as unverifiable).",
    )
    args = ap.parse_args(argv)

    if args.all_in:
        paths = _env_files_in(args.all_in)
        if not paths:
            print(f"No env.* files found in {args.all_in}", file=sys.stderr)
            return 1
        files = [str(p) for p in paths]
    else:
        files = [args.env_file]

    errors: list[tuple[str, str]] = []
    for path in files:
        try:
            refresh_env_file(path, verify=args.verify, allow_missing_digest=args.no_verify_missing)
            print(f"Refreshed {path}")
        except RefreshSecretsError as e:
            errors.append((path, str(e)))

    if errors:
        for path, msg in errors:
            print(f"ERROR [{path}]: {msg}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
