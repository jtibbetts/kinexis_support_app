Below is a full rewrite of the script into the exact layered layout we discussed, **preserving behavior and flags**:

- `env_file` positional arg
    
- `--verify`
    
- `--no-verify-missing`
    
- Uses `op item get ... --format json`
    
- Extracts env vars from 1Password **field `label` → env var name**, `value` → value
    
- Digest is computed over a canonicalized `KEY=value\n` sorted list
    
- Default digest algorithm is `hmac-sha256`
    
- HMAC key is taken from `REFRESH_SECRETS_HMAC_KEY` (same requirement as before)
    
- Writes atomically (`.tmp` then replace)
    
- Writes `updated_at` as UTC ISO8601 with `Z`
    

You can use this either:

- as a **standalone CLI** (optional entrypoint included), and/or
    
- as a **Django management command**: `python manage.py refresh_secrets env-staging --verify`
    

---

## File layout

your_app/  
  services/  
    secrets_refresh/  
      __init__.py  
      domain.py  
      op_client.py  
      fileio.py  
      service.py  
      cli.py                  # optional standalone entrypoint  
  management/  
    __init__.py  
    commands/  
      __init__.py  
      refresh_secrets.py

---

## `your_app/services/secrets_refresh/__init__.py`

__all__ = [  
    "RefreshSecretsError",  
    "DigestMismatchError",  
    "MissingDigestError",  
    "OpClient",  
    "refresh_env_file",  
]  
from .service import refresh_env_file  
from .op_client import OpClient  
from .service import RefreshSecretsError, DigestMismatchError, MissingDigestError

---

## `your_app/services/secrets_refresh/domain.py`

from __future__ import annotations  
  
import hashlib  
import hmac  
import re  
from dataclasses import dataclass  
from typing import Dict, List, Tuple  
  
  
HEADER_START = r"^#\s*@secrets:\s*$"  
HEADER_END = r"^#\s*@endsecrets\s*$"  
  
  
@dataclass(frozen=True)  
class SecretsHeader:  
    vault: str  
    items: List[str]  
    digest_alg: str = "hmac-sha256"  
    digest_hex: str | None = None  
    updated_at: str | None = None  
  
  
class RefreshSecretsError(RuntimeError):  
    """Base error for refresh-secrets operations."""  
  
  
def parse_header(lines: List[str]) -> Tuple[SecretsHeader, int, int]:  
    """  
    Parse the header block:  
  
    # @secrets:  
    #   vault: RUTA IT  
    #   items: db-staging, cache-redis  
    #   digest_alg: hmac-sha256  
    #   digest: <hex>  
    #   updated_at: <iso>  
    # @endsecrets  
  
    Returns (header, header_start_idx, header_end_idx) where indices include markers.  
    """  
    start_idx = None  
    end_idx = None  
  
    for i, line in enumerate(lines):  
        if start_idx is None and re.match(HEADER_START, line):  
            start_idx = i  
            continue  
        if start_idx is not None and re.match(HEADER_END, line):  
            end_idx = i  
            break  
  
    if start_idx is None or end_idx is None or end_idx <= start_idx:  
        raise RefreshSecretsError("Secrets header block not found or malformed.")  
  
    header_kv: Dict[str, str] = {}  
    for raw in lines[start_idx + 1 : end_idx]:  
        # YAML-ish key parsing; only comment lines are considered  
        m = re.match(r"^\s*#\s*([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$", raw)  
        if not m:  
            continue  
        k, v = m.group(1), m.group(2)  
        header_kv[k.strip()] = v.strip()  
  
    vault = header_kv.get("vault")  
    items = header_kv.get("items")  
    if not vault or not items:  
        raise RefreshSecretsError("Header must include 'vault' and 'items'.")  
  
    item_list = [x.strip() for x in items.split(",") if x.strip()]  
    if not item_list:  
        raise RefreshSecretsError("'items' list is empty.")  
  
    return (  
        SecretsHeader(  
            vault=vault,  
            items=item_list,  
            digest_alg=header_kv.get("digest_alg", "hmac-sha256"),  
            digest_hex=header_kv.get("digest"),  
            updated_at=header_kv.get("updated_at"),  
        ),  
        start_idx,  
        end_idx,  
    )  
  
  
def parse_env_body(lines: List[str], header_end_idx: int) -> Dict[str, str]:  
    """  
    Parse KEY=VALUE lines after the header. Ignores blank lines, comments, and invalid lines.  
    Values are preserved as raw strings (no unquoting).  
    """  
    env: Dict[str, str] = {}  
    for raw in lines[header_end_idx + 1 :]:  
        line = raw.strip()  
        if not line or line.startswith("#"):  
            continue  
        if "=" not in line:  
            continue  
        k, v = line.split("=", 1)  
        env[k.strip()] = v  
    return env  
  
  
def canonical_env_text(env: Dict[str, str]) -> str:  
    """  
    Canonical representation used for digesting:  
    sorted KEY=VALUE lines joined with \n, final trailing newline included.  
    """  
    parts = [f"{k}={env[k]}" for k in sorted(env.keys())]  
    return "\n".join(parts) + "\n"  
  
  
def compute_digest(env: Dict[str, str], alg: str, hmac_key: bytes | None) -> str:  
    """  
    Supported algorithms:  
      - sha256  
      - hmac-sha256 (default)  
    """  
    text = canonical_env_text(env).encode("utf-8")  
  
    a = alg.lower().replace("_", "-")  
    if a in ("sha256", "hash-sha256"):  
        return hashlib.sha256(text).hexdigest()  
  
    if a in ("hmac-sha256",):  
        if not hmac_key:  
            raise RefreshSecretsError(  
                "digest_alg is hmac-sha256 but no HMAC key provided. "  
                "Set REFRESH_SECRETS_HMAC_KEY."  
            )  
        return hmac.new(hmac_key, text, hashlib.sha256).hexdigest()  
  
    raise RefreshSecretsError(f"Unsupported digest_alg: {alg}")  
  
  
def render_header(header: SecretsHeader, digest_hex: str, updated_at: str) -> List[str]:  
    return [  
        "# @secrets:\n",  
        f"#   vault: {header.vault}\n",  
        f"#   items: {', '.join(header.items)}\n",  
        f"#   digest_alg: {header.digest_alg}\n",  
        f"#   digest: {digest_hex}\n",  
        f"#   updated_at: {updated_at}\n",  
        "# @endsecrets\n",  
        "\n",  
    ]  
  
  
def render_env_body(env: Dict[str, str]) -> List[str]:  
    lines: List[str] = []  
    for k in sorted(env.keys()):  
        lines.append(f"{k}={env[k]}\n")  
    return lines  
  
  
def render_updated_file(  
    header: SecretsHeader, env: Dict[str, str], digest_hex: str, updated_at: str  
) -> List[str]:  
    out: List[str] = []  
    out.extend(render_header(header, digest_hex, updated_at))  
    out.extend(render_env_body(env))  
    return out

---

## `your_app/services/secrets_refresh/op_client.py`

from __future__ import annotations  
  
import json  
import re  
import subprocess  
from typing import Dict, List, Protocol  
  
from .domain import RefreshSecretsError  
  
  
class OpRunner(Protocol):  
    def run(self, cmd: List[str]) -> str: ...  
  
  
class SubprocessOpRunner:  
    def run(self, cmd: List[str]) -> str:  
        try:  
            p = subprocess.run(  
                cmd,  
                check=True,  
                stdout=subprocess.PIPE,  
                stderr=subprocess.PIPE,  
                text=True,  
            )  
            return p.stdout  
        except subprocess.CalledProcessError as e:  
            raise RefreshSecretsError(  
                f"Command failed: {' '.join(cmd)}\n\nSTDERR:\n{e.stderr.strip()}"  
            ) from e  
  
  
class OpClient:  
    """  
    Minimal adapter around the `op` CLI.  
    """  
  
    def __init__(self, runner: OpRunner | None = None) -> None:  
        self._runner = runner or SubprocessOpRunner()  
  
    def item_get_json(self, vault: str, item: str) -> dict:  
        out = self._runner.run(  
            ["op", "item", "get", item, "--vault", vault, "--format", "json"]  
        )  
        try:  
            return json.loads(out)  
        except json.JSONDecodeError as e:  
            raise RefreshSecretsError(f"Failed to parse JSON for item {item}: {e}") from e  
  
  
def fields_to_env(item_json: dict) -> Dict[str, str]:  
    """  
    Convert 1Password item fields into env vars.  
  
    Uses:  
      - field['label'] as env var key  
      - field['value'] as value (stringified)  
  
    Skips fields without label/value and rejects invalid env keys.  
    """  
    env: Dict[str, str] = {}  
    fields = item_json.get("fields", []) or []  
    for f in fields:  
        label = f.get("label")  
        value = f.get("value")  
        if not label or value is None:  
            continue  
        if not isinstance(label, str):  
            continue  
  
        # Skip structured values  
        if isinstance(value, (dict, list)):  
            continue  
  
        key = label.strip()  
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):  
            raise RefreshSecretsError(  
                f"Invalid env var name from 1Password field label: {key!r}"  
            )  
  
        env[key] = str(value)  
  
    return env  
  
  
def fetch_env_from_items(op: OpClient, vault: str, items: List[str]) -> Dict[str, str]:  
    """  
    Merge env vars from all items. Collision policy: later items override earlier ones.  
    """  
    merged: Dict[str, str] = {}  
    for item in items:  
        item_json = op.item_get_json(vault, item)  
        item_env = fields_to_env(item_json)  
        for k, v in item_env.items():  
            merged[k] = v  
    return merged

---

## `your_app/services/secrets_refresh/fileio.py`

from __future__ import annotations  
  
import os  
from typing import List  
  
from .domain import RefreshSecretsError  
  
  
def read_lines(path: str) -> List[str]:  
    try:  
        with open(path, "r", encoding="utf-8") as f:  
            return f.readlines()  
    except FileNotFoundError as e:  
        raise RefreshSecretsError(f"File not found: {path}") from e  
    except OSError as e:  
        raise RefreshSecretsError(f"Failed to read file: {path} ({e})") from e  
  
  
def atomic_write_lines(path: str, lines: List[str]) -> None:  
    tmp_path = path + ".tmp"  
    try:  
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:  
            f.writelines(lines)  
        os.replace(tmp_path, path)  
    except OSError as e:  
        raise RefreshSecretsError(f"Failed to write file: {path} ({e})") from e

---

## `your_app/services/secrets_refresh/service.py`

from __future__ import annotations  
  
import datetime as dt  
import os  
from typing import Callable  
  
from .domain import (  
    RefreshSecretsError,  
    SecretsHeader,  
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
    new_digest = compute_digest(fresh_env, header.digest_alg, hmac_key)  
  
    out_lines = render_updated_file(header, fresh_env, new_digest, updated_at)  
    atomic_write_lines(path, out_lines)

---

## Optional: `your_app/services/secrets_refresh/cli.py` (standalone CLI entrypoint)

from __future__ import annotations  
  
import argparse  
import sys  
  
from .domain import RefreshSecretsError  
from .service import refresh_env_file  
  
  
def main(argv: list[str] | None = None) -> int:  
    ap = argparse.ArgumentParser()  
    ap.add_argument("env_file", help="Path to .env file to refresh (e.g. env-staging)")  
    ap.add_argument(  
        "--verify",  
        action="store_true",  
        help="Verify existing digest matches current env contents before refreshing.",  
    )  
    ap.add_argument(  
        "--no-verify-missing",  
        action="store_true",  
        help="If digest is missing, do not fail verification (treat as unverifiable).",  
    )  
    args = ap.parse_args(argv)  
  
    refresh_env_file(  
        args.env_file,  
        verify=args.verify,  
        allow_missing_digest=args.no_verify_missing,  
    )  
    print(f"Refreshed {args.env_file}")  
    return 0  
  
  
if __name__ == "__main__":  
    try:  
        raise SystemExit(main())  
    except RefreshSecretsError as e:  
        print(f"ERROR: {e}", file=sys.stderr)  
        raise SystemExit(2)

---

## Django management command wrapper

### `your_app/management/commands/refresh_secrets.py`

from __future__ import annotations  
  
from django.core.management.base import BaseCommand, CommandError  
  
from your_app.services.secrets_refresh.domain import RefreshSecretsError  
from your_app.services.secrets_refresh.service import refresh_env_file  
  
  
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

> Replace `your_app` in the import path with your actual Django app name.

---

## How to run

**As management command:**

python manage.py refresh_secrets env-staging --verify

**Or standalone CLI:**

python -m your_app.services.secrets_refresh.cli env-staging --verify

---

## Notes (matching your existing behavior)

- If `digest_alg` is `hmac-sha256` (default) and `REFRESH_SECRETS_HMAC_KEY` is not set, it errors (same as before).
    
- `--verify` checks the digest against what’s currently in the file; if mismatch, it refuses to update.
    
- `--no-verify-missing` only affects the case where digest is absent and `--verify` is set.
    

If you want, I can also add:

- `--check` mode (verify-only, don’t write)
    
- better collision reporting (warn if multiple items define same env var)
    
- filtering by 1Password _section_ label (e.g., export only “staging” section fields)