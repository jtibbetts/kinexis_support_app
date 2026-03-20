from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from kinexis_support.scripts.dokku_config_set import (
    _DEV_ENVS,
    push_env,
)
from kinexis_support.services.secrets_refresh.domain import RefreshSecretsError


class Command(BaseCommand):
    help = "Push env vars from managed env file(s) to Dokku via SSH."

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument(
            "env_file",
            nargs="?",
            help="Path to a single env file to push.",
        )
        target.add_argument(
            "--all-in",
            metavar="DIRECTORY",
            help="Push all non-dev env.* files in the given directory.",
        )

        parser.add_argument(
            "--ssh",
            required=True,
            help="SSH target for the Dokku host, e.g. dokku@dokku.kinexis.com",
        )
        parser.add_argument(
            "--app",
            default=None,
            help="Override the Dokku app name (single file only).",
        )
        parser.add_argument(
            "--no-restart",
            action="store_true",
            help="Pass --no-restart to dokku config:import.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print what would be pushed without executing.",
        )

    def handle(self, *args, **options):
        if options["app"] and options["all_in"]:
            raise CommandError("--app cannot be used with --all-in")

        if options["all_in"]:
            all_paths = sorted(Path(options["all_in"]).expanduser().glob("env.*"))
            files: list[str] = []
            for p in all_paths:
                env = p.name.split(".", 1)[1] if "." in p.name else ""
                if env in _DEV_ENVS:
                    self.stdout.write(f"Skipping {p.name} (dev environment)")
                    continue
                files.append(str(p))
            if not files:
                raise CommandError(f"No pushable env.* files found in {options['all_in']}")
        else:
            files = [options["env_file"]]

        errors: list[tuple[str, str]] = []
        for env_file in files:
            try:
                push_env(
                    env_file,
                    ssh=options["ssh"],
                    app=options["app"],
                    no_restart=options["no_restart"],
                    dry_run=options["dry_run"],
                )
                if not options["dry_run"]:
                    self.stdout.write(self.style.SUCCESS(f"Pushed {env_file}"))
            except (ValueError, RuntimeError, RefreshSecretsError) as e:
                errors.append((env_file, str(e)))

        if errors:
            for path, msg in errors:
                self.stderr.write(self.style.ERROR(f"ERROR [{path}]: {msg}"))
            raise CommandError("One or more files failed to push.")
