from __future__ import annotations

import os
import subprocess
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError


DEFAULT_CONFIG_ROOT = "~/.config"


def _discover_apps(config_root: Path) -> list[str]:
    """Valid apps: subdirectories of config_root that contain a templates/ subdir."""
    if not config_root.is_dir():
        return []
    return sorted(
        p.name for p in config_root.iterdir()
        if p.is_dir() and (p / "templates").is_dir()
    )


def _inject(template: Path, out_path: Path, env: dict | None = None) -> None:
    """Run `op inject` to resolve a template into out_path. Raises on failure."""
    proc = subprocess.run(
        ["op", "inject", "-f", "-i", str(template), "-o", str(out_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"op inject failed (exit {proc.returncode})")


class Command(BaseCommand):
    help = (
        "Render an application's env files from templates using `op inject` "
        "(1Password). Renders every env.* file in ~/.config/<app>/templates/ and "
        "writes each rendered file to ~/.config/<app>/. Valid apps are discovered "
        "on the fly: subdirectories of ~/.config that contain a templates/ subdir."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "app",
            help="Target application (a subdirectory of ~/.config with a templates/ subdir).",
        )
        parser.add_argument(
            "--config-root",
            default=DEFAULT_CONFIG_ROOT,
            metavar="DIRECTORY",
            help=f"Root directory holding per-app config dirs (default: {DEFAULT_CONFIG_ROOT}).",
        )
        parser.add_argument(
            "--service-account",
            action="store_true",
            help=(
                "Use OP_SERVICE_ACCOUNT_TOKEN from the environment (for headless/CI). "
                "By default it is ignored so rendering uses your full-access 1Password "
                "session, avoiding deadlocks when a restricted token is loaded by direnv."
            ),
        )

    def handle(self, *args, **options):
        config_root = Path(options["config_root"]).expanduser()
        app = options["app"]

        # Authoring tool: render as the human's full-access identity by default.
        # A restricted service-account token (often loaded into the shell by direnv)
        # can't see the vaults the templates reference, so strip it unless opted in.
        env = dict(os.environ)
        if not options["service_account"]:
            env.pop("OP_SERVICE_ACCOUNT_TOKEN", None)

        valid = _discover_apps(config_root)
        if app not in valid:
            available = ", ".join(valid) if valid else "(none found)"
            raise CommandError(
                f"Unknown app {app!r}. Valid apps in {config_root}: {available}"
            )

        out_dir = config_root / app
        templates_dir = out_dir / "templates"

        templates = sorted(p for p in templates_dir.glob("env.*") if p.is_file())
        if not templates:
            raise CommandError(f"No env.* templates found in {templates_dir}")

        errors: list[tuple[str, str]] = []
        for template in templates:
            out_path = out_dir / template.name
            try:
                _inject(template, out_path, env=env)
                self.stdout.write(self.style.SUCCESS(f"Rendered {template.name} -> {out_path}"))
            except RuntimeError as e:
                errors.append((template.name, str(e)))

        if errors:
            for name, msg in errors:
                self.stderr.write(self.style.ERROR(f"ERROR [{name}]: {msg}"))
            raise CommandError(f"One or more templates failed to render for {app!r}.")
