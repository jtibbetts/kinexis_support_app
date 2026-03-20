from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .domain import RefreshSecretsError, parse_env_body, parse_header
from .fileio import read_lines
from .service import refresh_env_file


_DOKKU_SSH = "root@dokku2.kinexis.com"

_ENV_TO_APP_SUFFIX: dict[str, str] = {
    "prod":       "",
    "production": "",
    "staging":    "-staging",
}
_DEV_ENVS = {"dev", "development"}


def _env_files_in(directory: str) -> list[Path]:
    return sorted(
        p for p in Path(directory).glob("env.*")
        if _has_secrets_header(p)
    )


def _has_secrets_header(path: Path) -> bool:
    try:
        return any("@secrets:" in line for line in path.read_text(encoding="utf-8").splitlines())
    except OSError:
        return False


def _derive_app_name(path: Path) -> str:
    project = path.parent.name
    parts = path.name.split(".", 1)
    if len(parts) < 2:
        raise ValueError(f"Cannot derive environment from filename: {path.name!r}")
    env = parts[1]
    if env in _DEV_ENVS:
        raise ValueError(f"{path.name} is a dev environment; skipping Dokku deploy.")
    if env not in _ENV_TO_APP_SUFFIX:
        raise ValueError(
            f"Unknown environment {env!r} in {path.name}. "
            f"Expected one of: {', '.join(sorted(_ENV_TO_APP_SUFFIX))}"
        )
    return f"{project}{_ENV_TO_APP_SUFFIX[env]}"


def _deploy_to_dokku(path: Path, ssh: str, no_restart: bool) -> None:
    lines = read_lines(str(path))
    _, _start, end_idx = parse_header(lines)
    env = parse_env_body(lines, end_idx)

    app_name = _derive_app_name(path)
    env_content = "".join(f"{k}={v}\n" for k, v in sorted(env.items()))
    tmp_dir = "/tmp/app.env"
    tmp_path = f"{tmp_dir}/{path.name}"

    # Ensure remote temp directory exists, then copy the file up
    proc1 = subprocess.run(
        ["ssh", ssh, f"mkdir -p {tmp_dir} && cat > {tmp_path}"],
        input=env_content,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc1.returncode != 0:
        raise RuntimeError(f"Failed to copy {path.name} to {ssh}:{tmp_path}: {proc1.stderr.strip()}")

    no_restart_flag = "--no-restart " if no_restart else ""

    # Clear all existing config vars first so stale keys don't linger
    proc2 = subprocess.run(
        ["ssh", ssh, f"dokku config:clear {no_restart_flag}{app_name}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc2.returncode != 0:
        raise RuntimeError(f"dokku config:clear failed for {app_name}: {proc2.stderr.strip()}")

    # Pass KEY=VALUE pairs to dokku via xargs -0 — avoids all shell quoting/escaping issues.
    # tr converts newlines to null bytes; xargs -0 splits on nulls and invokes dokku directly
    # (no shell involved), so values with spaces, braces, quotes, etc. are preserved exactly.
    proc3 = subprocess.run(
        ["ssh", ssh,
         f"grep -v '^#' {tmp_path} | grep -v '^$' | tr '\\n' '\\000' "
         f"| xargs -0 dokku config:set {no_restart_flag}{app_name}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc3.returncode != 0:
        raise RuntimeError(f"dokku config:set failed for {app_name}: {proc3.stderr.strip()}")
    if proc3.stdout.strip():
        print(proc3.stdout.strip())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Refresh self-describing env file(s) from 1Password."
    )

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
    ap.add_argument(
        "--no-ssh",
        action="store_true",
        help="Skip the Dokku deploy step (refresh only).",
    )
    ap.add_argument(
        "--no-restart",
        action="store_true",
        help="Pass --no-restart to dokku config:set when deploying.",
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
    for path_str in files:
        try:
            refresh_env_file(path_str, verify=args.verify, allow_missing_digest=args.no_verify_missing)
            print(f"Refreshed {path_str}")
        except RefreshSecretsError as e:
            errors.append((path_str, str(e)))
            continue

        if not args.no_ssh:
            path = Path(path_str).expanduser().resolve()
            try:
                _deploy_to_dokku(path, _DOKKU_SSH, args.no_restart)
                print(f"Deployed {path.name} to Dokku via {_DOKKU_SSH}")
            except ValueError as e:
                msg = str(e)
                if "dev environment" in msg.lower():
                    print(f"Skipped deploy for {path.name}: {msg}")
                else:
                    errors.append((path_str, f"Deploy failed: {msg}"))
            except RuntimeError as e:
                errors.append((path_str, f"Deploy failed: {e}"))

    if errors:
        for path, msg in errors:
            print(f"ERROR [{path}]: {msg}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
