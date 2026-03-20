from __future__ import annotations

import subprocess
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from kinexis_support.services.secrets_refresh.domain import (
    RefreshSecretsError,
    parse_env_body,
    parse_header,
)
from kinexis_support.services.secrets_refresh.fileio import read_lines
from kinexis_support.services.secrets_refresh.service import refresh_env_file


_DOKKU_SSH = "root@dokku2.kinexis.com"

_ENV_TO_APP_SUFFIX: dict[str, str] = {
    "prod":       "",
    "production": "",
    "staging":    "-staging",
}
_DEV_ENVS = {"dev", "development"}


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
    if proc2.stdout.strip():
        print(proc2.stdout.strip())


class Command(BaseCommand):
    help = (
        "Refresh self-describing env file(s) from 1Password. "
        "With no arguments, refreshes all env.* files in the current directory."
    )

    @staticmethod
    def _has_secrets_header(path: Path) -> bool:
        try:
            return any("@secrets:" in line for line in path.read_text(encoding="utf-8").splitlines())
        except OSError:
            return False

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument(
            "env_file",
            nargs="?",
            help="Path to a single .env file to refresh.",
        )
        target.add_argument(
            "--all-in",
            metavar="DIRECTORY",
            help="Refresh all env.* files in the given directory.",
        )
        parser.add_argument(
            "--verify",
            action="store_true",
            help="Verify existing digest matches current env contents before refreshing.",
        )
        parser.add_argument(
            "--no-verify-missing",
            action="store_true",
            help="If digest is missing, do not fail verification (treat as unverifiable).",
        )
        parser.add_argument(
            "--no-ssh",
            action="store_true",
            help="Skip the Dokku deploy step (refresh only).",
        )
        parser.add_argument(
            "--no-restart",
            action="store_true",
            help="Pass --no-restart to dokku config:set when deploying.",
        )

    def handle(self, *args, **options):
        verify = bool(options["verify"])
        allow_missing = bool(options["no_verify_missing"])
        no_ssh = bool(options.get("no_ssh"))
        no_restart = bool(options.get("no_restart"))

        if options["all_in"]:
            paths = sorted(
                p for p in Path(options["all_in"]).glob("env.*")
                if self._has_secrets_header(p)
            )
            if not paths:
                raise CommandError(f"No env.* files found in {options['all_in']}")
            files = [str(p) for p in paths]
        else:
            files = [options["env_file"]]

        errors: list[tuple[str, str]] = []
        for path_str in files:
            try:
                refresh_env_file(path_str, verify=verify, allow_missing_digest=allow_missing)
                self.stdout.write(self.style.SUCCESS(f"Refreshed {path_str}"))
            except RefreshSecretsError as e:
                errors.append((path_str, str(e)))
                continue

            if not no_ssh:
                path = Path(path_str).expanduser().resolve()
                try:
                    _deploy_to_dokku(path, _DOKKU_SSH, no_restart)
                    self.stdout.write(self.style.SUCCESS(f"Deployed {path.name} to Dokku via {_DOKKU_SSH}"))
                except ValueError as e:
                    msg = str(e)
                    if "dev environment" in msg.lower():
                        self.stdout.write(f"Skipped deploy for {path.name}: {msg}")
                    else:
                        errors.append((path_str, f"Deploy failed: {msg}"))
                except RuntimeError as e:
                    errors.append((path_str, f"Deploy failed: {e}"))

        if errors:
            for path, msg in errors:
                self.stderr.write(self.style.ERROR(f"ERROR [{path}]: {msg}"))
            raise CommandError("One or more files failed.")
