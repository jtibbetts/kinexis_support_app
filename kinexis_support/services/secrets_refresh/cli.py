from __future__ import annotations

import argparse
import sys

from .domain import RefreshSecretsError
from .service import refresh_env_file


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("env_file", help="Path to .env file to refresh (e.g. env-staging)")
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

    refresh_env_file(
        args.env_file,
        verify=args.verify,
        allow_missing_digest=args.no_verify_missing,
    )
    print(f"Refreshed {args.env_file}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RefreshSecretsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(2)
