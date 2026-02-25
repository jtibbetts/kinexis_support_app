Here’s a solid pattern (and a ready-to-run script) that matches what you described:

- **Each `.env-*` file contains a self-describing header** listing the **1Password item names** to read.
    
- The script:
    
    1. Reads the file
        
    2. Parses header (`items`, `vault`, etc.)
        
    3. Recomputes a **tamper-evident digest** over the _actual exported key/value pairs_
        
    4. Verifies it matches what’s stored in the file header
        
    5. Fetches fresh values from 1Password
        
    6. Writes updated env body + **timestamp** + **new digest**
        

### Recommended nomenclature in your design

- Vault: `RUTA IT`
    
- Item: `db-staging`, `cache-redis`, `django-default` (each item is a “bundle”)
    
- Field: each env var key/value (`DJANGO_SECRET_KEY`, etc.)
    

---

## Env file format

Use a comment header that’s easy to parse and safe to keep in `.env`:

```dotenv
# @secrets:
#   vault: RUTA IT
#   items: db-staging, cache-redis, django-default
#   digest_alg: hmac-sha256
#   digest: 7c8d... (hex)
#   updated_at: 2026-02-24T18:12:33Z
# @endsecrets

DJANGO_DEBUG=false
# ... rest of env vars written by script ...
```

Why HMAC and not plain SHA?  
A plain SHA digest only detects accidental changes. **HMAC** detects tampering _as long as the HMAC key is secret and stored elsewhere_ (not in the env file).

Store the HMAC key somewhere like:

- `REFRESH_SECRETS_HMAC_KEY` in your shell environment (not committed)
    
- or a separate 1Password item that your script reads first (then you’re “trusting” 1P as the authority, which is usually fine)
    

---

## What exactly is signed?

Sign a canonical representation of the env vars the script writes (the union of fields pulled from all listed items), e.g.:

- Sort keys
    
- Normalize newlines
    
- Represent as `KEY=value` lines joined with `\n`
    

That way the digest is stable and deterministic.

---

## `refresh-secrets.py` (complete script)

```python
#!/usr/bin/env python3
"""
refresh-secrets.py

Reads a .env file with a self-describing header that specifies:
- vault name
- comma-separated item names in that vault

Then:
- verifies the stored digest matches the current contents (optional but recommended)
- fetches item fields from 1Password (op CLI)
- writes env vars back out
- updates updated_at and digest

Requirements:
- op CLI installed and authenticated (op signin/session available)
- Python 3.10+
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple


HEADER_START = r"^#\s*@secrets:\s*$"
HEADER_END = r"^#\s*@endsecrets\s*$"


@dataclass
class SecretsHeader:
    vault: str
    items: List[str]
    digest_alg: str = "hmac-sha256"
    digest_hex: str | None = None
    updated_at: str | None = None


class RefreshSecretsError(RuntimeError):
    pass


def run_cmd(cmd: List[str]) -> str:
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


def parse_header(lines: List[str]) -> Tuple[SecretsHeader, int, int]:
    """
    Returns (header, header_start_index, header_end_index)
    where indices are inclusive of start and end marker lines.
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

    # Parse YAML-ish key: value lines between the markers
    header_kv: Dict[str, str] = {}
    for raw in lines[start_idx + 1 : end_idx]:
        # allow indentation, require "#"
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
    Parse env vars after the header. Only KEY=VALUE lines (ignores comments/blank).
    """
    env: Dict[str, str] = {}
    for raw in lines[header_end_idx + 1 :]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v  # preserve raw value (no unquoting)
    return env


def canonical_env_text(env: Dict[str, str]) -> str:
    """
    Canonical representation for digesting: sorted KEY=VALUE lines joined with \n.
    """
    parts = [f"{k}={env[k]}" for k in sorted(env.keys())]
    return "\n".join(parts) + "\n"


def compute_digest(env: Dict[str, str], alg: str, hmac_key: bytes | None) -> str:
    text = canonical_env_text(env).encode("utf-8")

    if alg.lower() in ("sha256", "hash-sha256"):
        return hashlib.sha256(text).hexdigest()

    if alg.lower() in ("hmac-sha256", "hmac_sha256"):
        if not hmac_key:
            raise RefreshSecretsError(
                "digest_alg is hmac-sha256 but no HMAC key provided. "
                "Set REFRESH_SECRETS_HMAC_KEY."
            )
        return hmac.new(hmac_key, text, hashlib.sha256).hexdigest()

    raise RefreshSecretsError(f"Unsupported digest_alg: {alg}")


def op_item_get_json(vault: str, item: str) -> dict:
    """
    Fetch item JSON from op CLI. Item can be UUID or name.
    """
    out = run_cmd(["op", "item", "get", item, "--vault", vault, "--format", "json"])
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RefreshSecretsError(f"Failed to parse JSON for item {item}: {e}") from e


def fields_to_env(item_json: dict) -> Dict[str, str]:
    """
    Convert 1Password item fields into env vars.

    Convention:
    - Use field 'label' as the env var name (must be a valid env key)
    - Use field 'value' as the value

    We ignore fields missing label/value, and we skip non-string values.
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
        # allow strings/numbers/bools; stringify
        if isinstance(value, (dict, list)):
            continue
        key = label.strip()

        # Basic env-key validation
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            # Skip silently or raise; I prefer raise to catch mistakes early.
            raise RefreshSecretsError(
                f"Invalid env var name from 1Password field label: {key!r}"
            )
        env[key] = str(value)
    return env


def merge_items_env(vault: str, items: List[str]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for item in items:
        item_json = op_item_get_json(vault, item)
        item_env = fields_to_env(item_json)

        # Collision policy: later items override earlier ones
        for k, v in item_env.items():
            merged[k] = v
    return merged


def render_header(h: SecretsHeader, digest_hex: str, updated_at: str) -> List[str]:
    return [
        "# @secrets:\n",
        f"#   vault: {h.vault}\n",
        f"#   items: {', '.join(h.items)}\n",
        f"#   digest_alg: {h.digest_alg}\n",
        f"#   digest: {digest_hex}\n",
        f"#   updated_at: {updated_at}\n",
        "# @endsecrets\n",
        "\n",
    ]


def render_env_body(env: Dict[str, str]) -> List[str]:
    lines = []
    for k in sorted(env.keys()):
        lines.append(f"{k}={env[k]}\n")
    return lines


def main() -> int:
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
    args = ap.parse_args()

    path = args.env_file
    if not os.path.exists(path):
        raise RefreshSecretsError(f"File not found: {path}")

    raw = open(path, "r", encoding="utf-8").readlines()
    header, start_idx, end_idx = parse_header(raw)
    existing_env = parse_env_body(raw, end_idx)

    hmac_key = os.environ.get("REFRESH_SECRETS_HMAC_KEY", "").encode("utf-8") or None

    if args.verify:
        if not header.digest_hex:
            if args.no_verify_missing:
                pass
            else:
                raise RefreshSecretsError("No digest in header; cannot verify.")
        else:
            current_digest = compute_digest(existing_env, header.digest_alg, hmac_key)
            if current_digest.lower() != header.digest_hex.lower():
                raise RefreshSecretsError(
                    "Digest verification FAILED.\n"
                    f"  expected: {header.digest_hex}\n"
                    f"  actual:   {current_digest}\n"
                    "Refusing to refresh because the env contents appear modified."
                )

    # Fetch fresh env from 1Password
    fresh_env = merge_items_env(header.vault, header.items)

    # Compute new digest and timestamp
    updated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    new_digest = compute_digest(fresh_env, header.digest_alg, hmac_key)

    out_lines: List[str] = []
    out_lines.extend(render_header(header, new_digest, updated_at))
    out_lines.extend(render_env_body(fresh_env))

    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(out_lines)

    os.replace(tmp_path, path)
    print(f"Refreshed {path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RefreshSecretsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(2)
```

---

## How you’d run it

```bash
export REFRESH_SECRETS_HMAC_KEY="$(op read 'op://RUTA IT/refresh-secrets-hmac/password')"
python3 refresh-secrets.py env-staging --verify
```

(That `op read ...` path is just an example; you can store the HMAC key however you like.)

---

## A couple of practical notes (so it doesn’t bite you later)

- **Item name collisions**: if two items define the same env var name, the script currently uses “later items win” (because the merge loop overwrites). That’s usually what you want.
    
- **Which fields become env vars**: this uses the 1Password field **`label`** as the env var key. So in 1Password, label your fields exactly `DJANGO_SECRET_KEY`, etc.
    
- If you want to support **sections** (e.g. “Production”, “Staging”) and only export from certain sections, we can extend `fields_to_env()` to filter on `section.id` / `section.label` (depending on what `op item get --format json` returns for your items).
    

If you paste one sample `op item get <item> --format json` (redacting values), I’ll tailor the field extraction to exactly match your item structure (Secure Note vs API Credential, sections, etc.) without guessing.