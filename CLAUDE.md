# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Development server
python manage.py runserver

# Run all tests
python manage.py test

# Run tests for a specific app
python manage.py test kinexis_support

# Refresh secrets via Django management command
python manage.py refresh_secrets <env-file> [--verify] [--no-verify-missing]

# Refresh secrets via standalone CLI
python -m kinexis_support.services.secrets_refresh.cli <env-file> [--verify]

# Install dependencies
poetry install
```

## Architecture

This is a **Django 6.0.1** app (Python 3.13+, Poetry) built around a single core feature: **secrets refresh** — pulling env vars from 1Password and writing them into self-describing `.env` files with integrity digests.

### Core Feature: `secrets_refresh` Service

Located in `kinexis_support/services/secrets_refresh/`, organized in strict layers:

| File | Layer | Role |
|------|-------|------|
| `domain.py` | Domain | Pure logic — no I/O. Parsing, digest computation, rendering. |
| `op_client.py` | Adapter | Wraps the `op` CLI (1Password). `OpClient` + `SubprocessOpRunner` (injectable for tests). |
| `fileio.py` | Adapter | File I/O — `read_lines()` and `atomic_write_lines()` (write to `.tmp` then `os.replace`). |
| `service.py` | Orchestration | `refresh_env_file()` coordinates all layers. Injects deps for testability. |
| `cli.py` | Entrypoint | Standalone argparse CLI. |

The same service is also exposed as a Django management command: `management/commands/refresh_secrets.py`.

### Self-Describing `.env` File Format

Env files managed by this app contain a metadata header block:

```
# @secrets:
#   vault: RUTA IT
#   items: db-staging, cache-redis
#   digest_alg: hmac-sha256
#   digest: <hex>
#   updated_at: 2024-01-15T12:00:00Z
# @endsecrets

KEY=value
OTHER_KEY=value
```

The digest is computed over a **canonicalized sorted `KEY=value\n`** representation of the env body.

### Required Environment Variable

- `REFRESH_SECRETS_HMAC_KEY` — required when `digest_alg` is `hmac-sha256` (the default). Set this before calling refresh.

### Testability Pattern

All layers use dependency injection. To test without real 1Password access, inject a mock `OpRunner` into `OpClient`, or inject a mock `OpClient` directly into `refresh_env_file()`. The `domain.py` functions are pure and require no mocking.

### `--verify` Flag Behavior

- `--verify`: Recomputes digest over current file contents and compares to stored digest. Refuses to refresh on mismatch.
- `--no-verify-missing`: When used with `--verify`, allows refresh even if no digest is present in the header.

### Other Utilities

- `kinexis_support/scripts/dokku_env_export.py` — exports Dokku app config vars to `.env` files (supports SSH to remote hosts).
