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
  
  
def apply_substitutions(
    env: Dict[str, str], now: str, app_name: str = "", app_env: str = ""
) -> Dict[str, str]:
    """
    Replace placeholder tokens in env values.
    Supported placeholders:
      {now}      — current UTC ISO timestamp (same as updated_at)
      {app_name} — name of the app (parent directory of the env file)
      {app_env}  — environment name (suffix after "env." in the filename)
    """
    subs = {"{now}": now, "{app_name}": app_name, "{app_env}": app_env}
    return {k: _apply(v, subs) for k, v in env.items()}


def _apply(value: str, subs: Dict[str, str]) -> str:
    for placeholder, replacement in subs.items():
        value = value.replace(placeholder, replacement)
    return value


def render_updated_file(  
    header: SecretsHeader, env: Dict[str, str], digest_hex: str, updated_at: str  
) -> List[str]:  
    out: List[str] = []  
    out.extend(render_header(header, digest_hex, updated_at))  
    out.extend(render_env_body(env))  
    return out
