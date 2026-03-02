from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from kinexis_support.services.secrets_refresh.domain import RefreshSecretsError
from kinexis_support.services.secrets_refresh.service import refresh_env_file


class Command(BaseCommand):
    help = "Refresh self-describing env file(s) by pulling fields from a 1Password vault."

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

    def handle(self, *args, **options):
        verify = bool(options["verify"])
        allow_missing = bool(options["no_verify_missing"])

        if options["all_in"]:
            paths = sorted(Path(options["all_in"]).glob("env.*"))
            if not paths:
                raise CommandError(f"No env.* files found in {options['all_in']}")
            files = [str(p) for p in paths]
        else:
            files = [options["env_file"]]

        errors: list[tuple[str, str]] = []
        for path in files:
            try:
                refresh_env_file(path, verify=verify, allow_missing_digest=allow_missing)
                self.stdout.write(self.style.SUCCESS(f"Refreshed {path}"))
            except RefreshSecretsError as e:
                errors.append((path, str(e)))

        if errors:
            for path, msg in errors:
                self.stderr.write(self.style.ERROR(f"ERROR [{path}]: {msg}"))
            raise CommandError("One or more files failed to refresh.")
