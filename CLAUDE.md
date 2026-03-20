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

# Refresh all env.* files in the current directory (default behavior)
poetry run python manage.py refresh_secrets

# Refresh a single env file
poetry run python manage.py refresh_secrets <env-file> [--verify] [--no-verify-missing]

# Refresh all env.* files in a directory
poetry run python manage.py refresh_secrets --all-in <directory>

# Refresh and deploy to Dokku (skips dev envs automatically)
poetry run python manage.py refresh_secrets --ssh ubuntu@dokku2.kinexis.com [--no-restart]

# Refresh secrets via standalone CLI (default: all env.* in current directory)
poetry run python -m kinexis_support.services.secrets_refresh.cli

# Refresh secrets via standalone CLI (single file)
poetry run python -m kinexis_support.services.secrets_refresh.cli <env-file> [--verify]

# Refresh secrets via standalone CLI (all files in directory)
poetry run python -m kinexis_support.services.secrets_refresh.cli --all-in <directory>

# Refresh and deploy via standalone CLI
poetry run python -m kinexis_support.services.secrets_refresh.cli --ssh ubuntu@dokku2.kinexis.com [--no-restart]

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

This is a **Django app** (Python 3.11+, Poetry) built around a single core feature: **secrets refresh** — pulling env vars from 1Password and writing them into self-describing `.env` files with integrity digests. These files are loaded by `direnv` in development to simulate the production/staging environment.

### Env File Locations

Env files live at `~/.config/<project>/env.<environment>`:

| File | Dokku app |
|------|-----------|
| `~/.config/<project>/env.dev` | dev only — not pushed to Dokku |
| `~/.config/<project>/env.staging` | `<project>-staging` |
| `~/.config/<project>/env.prod` | `<project>` |

### Core Feature: `secrets_refresh` Service

Located in `kinexis_support/services/secrets_refresh/`, organized in strict layers:

| File | Layer | Role |
|------|-------|------|
| `domain.py` | Domain | Pure logic — no I/O. Parsing, digest computation, rendering, substitutions. |
| `op_client.py` | Adapter | Wraps the `op` CLI (1Password). Parses notes field as `KEY=value` lines. |
| `fileio.py` | Adapter | File I/O — creates missing directories and skeleton files on first run. |
| `service.py` | Orchestration | `refresh_env_file()` coordinates all layers. Injects deps for testability. |
| `cli.py` | Entrypoint | Standalone argparse CLI. |

The same service is also exposed as a Django management command: `kinexis_support/management/commands/refresh_secrets.py`.

### Self-Describing `.env` File Format

```
# @secrets:
#   vault: RUTA IT
#   items: app:dev, db:sqlite, svc:ai
#   digest_alg: hmac-sha256
#   digest: <hex>
#   updated_at: 2024-01-15T12:00:00Z
# @endsecrets

KEY=value
OTHER_KEY=value
```

The digest is computed over a **canonicalized sorted `KEY=value\n`** representation of the env body.

### 1Password Item Format

Items store all env vars in the **Notes field** as `KEY=value` lines (one per line). Blank lines and `#` comments are ignored. The `op` CLI built-in fields (`notesPlain`, `username`, `password`) are skipped automatically.

### Value Substitutions

Placeholders in any value are replaced at refresh time:

| Placeholder | Replaced with |
|-------------|---------------|
| `{now}` | Current UTC ISO timestamp (same as `updated_at`) |
| `{app_name}` | Parent directory name of the env file (e.g. `openchannel`) |
| `{app_env}` | Filename suffix after `env.` (e.g. `dev`, `staging`, `prod`) |

Example:
```
APP_NAME={app_name}
APP_ENV={app_env}
GENERATED_AT={now}
```

### Required Environment Variable

- `REFRESH_SECRETS_HMAC_KEY` — required when `digest_alg` is `hmac-sha256` (the default). Set globally in shell config.

### Testability Pattern

All layers use dependency injection. To test without real 1Password access, inject a mock `OpRunner` into `OpClient`, or inject a mock `OpClient` directly into `refresh_env_file()`. The `domain.py` functions are pure and require no mocking.

### `--verify` Flag Behavior

- `--verify`: Recomputes digest over current file contents and compares to stored digest. Refuses to refresh on mismatch.
- `--no-verify-missing`: When used with `--verify`, allows refresh even if no digest is present in the header.

### Other Utilities

- `kinexis_support/scripts/dokku_env_export.py` — exports Dokku app config vars to `.env` files (supports SSH to remote hosts).
- `kinexis_support/scripts/dokku_config_set.py` — pushes env vars from a managed env file to a Dokku app via `config:import` over SSH.
