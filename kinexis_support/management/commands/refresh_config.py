from __future__ import annotations

import subprocess
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError


DEFAULT_TEMPLATES_DIR = "~/.config/kinexis_support/templates"


def _inject(template: Path, out_path: Path) -> None:
    """Run `op inject` to resolve a template into out_path. Raises on failure."""
    proc = subprocess.run(
        ["op", "inject", "-f", "-i", str(template), "-o", str(out_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"op inject failed (exit {proc.returncode})")


class Command(BaseCommand):
    help = (
        "Render config file(s) from templates using `op inject` (1Password). "
        "With no arguments, renders every file in the templates directory; "
        "each rendered file is written to the templates directory's parent."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "template",
            nargs="?",
            help=(
                "Render only this template. May be a bare filename (resolved "
                "inside --templates-dir) or a path to a template file."
            ),
        )
        parser.add_argument(
            "--templates-dir",
            default=DEFAULT_TEMPLATES_DIR,
            metavar="DIRECTORY",
            help=f"Directory containing template files (default: {DEFAULT_TEMPLATES_DIR}).",
        )
        parser.add_argument(
            "--out-dir",
            metavar="DIRECTORY",
            help="Where to write rendered files (default: the templates directory's parent).",
        )

    def handle(self, *args, **options):
        templates_dir = Path(options["templates_dir"]).expanduser()
        out_dir = (
            Path(options["out_dir"]).expanduser()
            if options["out_dir"]
            else templates_dir.parent
        )

        if options["template"]:
            arg = options["template"]
            template = Path(arg).expanduser()
            if not template.is_absolute() and template.parent == Path("."):
                template = templates_dir / arg
            if not template.is_file():
                raise CommandError(f"Template not found: {template}")
            templates = [template]
        else:
            if not templates_dir.is_dir():
                raise CommandError(f"Templates directory not found: {templates_dir}")
            templates = sorted(
                p for p in templates_dir.iterdir()
                if p.is_file() and not p.name.startswith(".")
            )
            if not templates:
                raise CommandError(f"No templates found in {templates_dir}")

        out_dir.mkdir(parents=True, exist_ok=True)

        errors: list[tuple[str, str]] = []
        for template in templates:
            out_path = out_dir / template.name
            try:
                _inject(template, out_path)
                self.stdout.write(self.style.SUCCESS(f"Rendered {template.name} -> {out_path}"))
            except RuntimeError as e:
                errors.append((template.name, str(e)))

        if errors:
            for name, msg in errors:
                self.stderr.write(self.style.ERROR(f"ERROR [{name}]: {msg}"))
            raise CommandError("One or more templates failed to render.")
