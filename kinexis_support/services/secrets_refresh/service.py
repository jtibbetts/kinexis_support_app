from __future__ import annotations

import datetime as dt
import os
from typing import Callable

from .domain import (
    RefreshSecretsError,
    SecretsHeader,
    apply_substitutions,
    compute_digest,
    parse_env_body,
    parse_header,
    render_updated_file,
)
from .fileio import atomic_write_lines, read_lines
from .op_client import OpClient, fetch_env_from_items


class DigestMismatchError(RefreshSecretsError):
    pass


class MissingDigestError(RefreshSecretsError):
    pass


def default_now_iso_utc() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_hmac_key_from_env() -> bytes | None:
    s = os.environ.get("REFRESH_SECRETS_HMAC_KEY", "")
    return s.encode("utf-8") if s else None


def refresh_env_file(
        path: str,
        *,
        verify: bool,
        allow_missing_digest: bool,
        op: OpClient | None = None,
        hmac_key: bytes | None = None,
        now_iso_utc: Callable[[], str] = default_now_iso_utc,
) -> None:
    """
    Orchestrates:
      - parse header + existing env
      - optional digest verification against existing env
      - fetch fresh env from 1Password
      - compute new digest + timestamp
      - write updated file atomically

    Behavior and flags match the original script.
    """
    op = op or OpClient()
    hmac_key = hmac_key if hmac_key is not None else load_hmac_key_from_env()

    lines = read_lines(path)
    header, _start_idx, end_idx = parse_header(lines)
    existing_env = parse_env_body(lines, end_idx)

    if verify:
        if not header.digest_hex:
            if not allow_missing_digest:
                raise MissingDigestError("No digest in header; cannot verify.")
        else:
            actual = compute_digest(existing_env, header.digest_alg, hmac_key)
            if actual.lower() != header.digest_hex.lower():
                raise DigestMismatchError(
                    "Digest verification FAILED.\n"
                    f"  expected: {header.digest_hex}\n"
                    f"  actual:   {actual}\n"
                    "Refusing to refresh because the env contents appear modified."
                )

    fresh_env = fetch_env_from_items(op, header.vault, header.items)

    updated_at = now_iso_utc()
    fresh_env = apply_substitutions(fresh_env, updated_at)
    new_digest = compute_digest(fresh_env, header.digest_alg, hmac_key)

    out_lines = render_updated_file(header, fresh_env, new_digest, updated_at)
    atomic_write_lines(path, out_lines)
