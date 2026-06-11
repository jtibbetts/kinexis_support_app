# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

> **Note:** Use `poetry run python` (not bare `python`) — the system Python is not in the project venv.

```bash
# Development server
poetry run python manage.py runserver

# Run all tests
poetry run python manage.py test

# Run tests for a specific app
poetry run python manage.py test kinexis_support

# Render an app's env files from templates via `op inject` (1Password)
poetry run python manage.py refresh_config <app>

# Use a service-account token (OP_SERVICE_ACCOUNT_TOKEN) instead of the
# interactive 1Password session — for headless/CI runs
poetry run python manage.py refresh_config <app> --service-account

# Override the config root (default ~/.config) — useful for testing
poetry run python manage.py refresh_config <app> --config-root <directory>

# Push env vars to Dokku via SSH (single file)
poetry run python -m kinexis_support.scripts.dokku_config_set <env-file> --ssh dokku@<host>

# Push all non-dev env files in a directory to Dokku
poetry run python -m kinexis_support.scripts.dokku_config_set --all-in <directory> --ssh dokku@<host>

# Dry run Dokku push (no changes made)
poetry run python -m kinexis_support.scripts.dokku_config_set --all-in <directory> --ssh dokku@<host> --dry-run

# Install dependencies
poetry install
```

## Architecture

This is a **Django app** (Python 3.11+, Poetry) built around a single core feature: **config refresh** — rendering self-describing `.env` files from templates that hold 1Password secret references, using `op inject`. These files are loaded by `direnv` in development to simulate the production/staging environment.

### Env File Locations

Each app has a config directory under `~/.config/`. Templates live in a `templates/` subdir; rendered output is written to the app dir (the parent of `templates/`):

```
~/.config/<app>/
├── templates/
│   ├── env.dev          # template with {{ op://... }} references
│   ├── env.staging
│   └── env.prod
├── env.dev              # rendered output (op inject)
├── env.staging
└── env.prod
```

| File | Dokku app |
|------|-----------|
| `~/.config/<app>/env.dev` | dev only — not pushed to Dokku |
| `~/.config/<app>/env.staging` | `<app>-staging` |
| `~/.config/<app>/env.prod` | `<app>` |

### Core Feature: `refresh_config`

Management command: `kinexis_support/management/commands/refresh_config.py`.

- Takes one positional argument: the target **app**.
- Valid apps are discovered **on the fly**: subdirectories of `~/.config` that contain a `templates/` subdir.
- Renders every `env.*` file in `~/.config/<app>/templates/` through `op inject` and writes each rendered file (same name) to `~/.config/<app>/`.
- By default it **strips `OP_SERVICE_ACCOUNT_TOKEN`** from the `op inject` subprocess so rendering runs as the user's full-access 1Password session. This avoids a deadlock when `direnv` has loaded a restricted service-account token that can't see the referenced vaults. `--service-account` opts back in for headless/CI.
- `--config-root` overrides the `~/.config` root.

### Template Format

Templates are plain `KEY=value` files; secret values use 1Password secret references resolved by `op inject`:

```
APP_ENV=dev
DATABASE_URL=postgresql://user:{{ op://Crypta/postgresql-password/notesPlain }}@host/db
SECRET_KEY={{ op://Crypta/dev-secret-key/credential }}
```

A reference is `op://<vault>/<item-name-or-uuid>/<field>`. The vault segment is optional when the item is identified by UUID.

### `secrets_refresh` Helpers (retained)

`kinexis_support/services/secrets_refresh/` previously held a digest-based refresh service. That service and its CLI/command were removed in favor of `refresh_config`. Two pure-logic modules remain because `dokku_config_set` still uses them:

| File | Role |
|------|------|
| `domain.py` | Pure logic — parsing the self-describing `# @secrets:` header and env body, digest helpers, `RefreshSecretsError`. No I/O. |
| `fileio.py` | File I/O helpers (`read_lines`, etc.). |

### Other Utilities

- `kinexis_support/scripts/dokku_env_export.py` — exports Dokku app config vars to `.env` files (supports SSH to remote hosts).
- `kinexis_support/scripts/dokku_config_set.py` — pushes env vars from a managed env file to a Dokku app via `config:import` over SSH. Also exposed as the `dokku_config_set` management command.
