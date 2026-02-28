from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from kinexis_support.services.secrets_refresh.domain import RefreshSecretsError
from kinexis_support.services.secrets_refresh.service import refresh_env_file


class Command(BaseCommand):
    help = "Refresh a self-describing env file by pulling item fields from a 1Password vault."

    def add_arguments(self, parser):
        parser.add_argument(
            "env_file",
            help="Path to .env file to refresh (e.g. env-staging)",
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
        env_file = options["env_file"]
        verify = bool(options["verify"])
        allow_missing = bool(options["no_verify_missing"])

        try:
            refresh_env_file(
                env_file,
                verify=verify,
                allow_missing_digest=allow_missing,
            )
        except RefreshSecretsError as e:
            raise CommandError(str(e)) from e

        self.stdout.write(self.style.SUCCESS(f"Refreshed {env_file}"))



