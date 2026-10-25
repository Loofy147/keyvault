"""Credential-injecting HTTP client.

The caller supplies a credential *name*; the secret is attached here and never returned.
Policy: https only (loopback http only when KEYVAULT_ALLOW_LOOPBACK_HTTP=1), host must match the
credential's allowlist, method must be enabled for the credential, redirects are not followed,
callers cannot set auth headers/params, responses are text-only, size-capped and scrubbed of the
secret (best effort: raw, URL-encoded and base64 forms of the value).
"""
from __future__ import annotations

import base64
import os
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

import httpx

from . import __version__
from .vault import Credential, audit, host_matches

MAX_BODY_BYTES = 100_000
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
FORBIDDEN_REQUEST_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "te", "upgrade",
}
KEEP_HEADERS = {"content-type", "location", "retry-after", "link", "etag", "last-modified", "date"}
KEEP_PREFIXES = ("x-ratelimit-", "ratelimit-", "x-request-id", "request-id")
TEXT_HINTS = ("text/", "json", "xml", "javascript", "yaml", "x-www-form-urlencoded", "graphql", "csv")


class ProxyError(ValueError):
    """A policy denial or request failure. Messages never contain secret values."""


# --------------------------------------------------------------------------- redaction

def _variants(cred: Credential) -> list:
    v = cred.value
    forms = {v, quote(v, safe=""), quote_plus(v), base64.b64encode(v.encode()).decode()}
    if cred.kind == "basic":
        password = v.partition(":")[2]
        if len(password) >= 6:
            forms.add(password)
    return sorted((f for f in forms if len(f) >= 4), key=len, reverse=True)


def redact(text: str, cred: Credential, variants: list | None = None) -> tuple:
    n = 0
    for f in variants or _variants(cred):
        if f in text:
            n += text.count(f)
            text = text.replace(f, f"[REDACTED:{cred.name}]")
    return text, n


def _textual(ctype: str, raw: bytes) -> bool:
    c = ctype.lower()
    if any(h in c for h in TEXT_HINTS):
        return True
    if not c:
        try:
            raw.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    return False


# --------------------------------------------------------------------------- request planning

def _plan(cred: Credential, method: str, url: str, headers: dict | None, params: dict | None) -> dict:
    method = str(method or "").upper()
    if cred.kind == "none":
        raise ProxyError(f"credential '{cred.name}' has no HTTP auth configured (kind=none); it is env-only")
    if method not in cred.methods:
        raise ProxyError(
            f"method {method or '(empty)'} is not enabled for credential '{cred.name}' "
            f"(enabled: {', '.join(cred.methods)}); the owner can enable more with "
            f"`keyvault edit {cred.name} --methods ...`"
        )
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ProxyError("URL must be one absolute URL without spaces, control characters or backslashes")
    try:
        parts = urlsplit(url)
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        raise ProxyError("malformed URL") from None
    if "@" in parts.netloc:
        raise ProxyError("URLs with embedded credentials are not allowed")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ProxyError("only https:// URLs are allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ProxyError("URL has no host")
    loopback_ok = host in LOOPBACK and os.environ.get("KEYVAULT_ALLOW_LOOPBACK_HTTP") == "1"
    if scheme == "http" and not loopback_ok:
        raise ProxyError("only https:// URLs are allowed")
    if not any(host_matches(host, pat) for pat in cred.hosts):
        raise ProxyError(
            f"host '{host}' is not allowed for credential '{cred.name}' (allowed: {', '.join(cred.hosts)})"
        )
    try:  # two URL parsers must agree about the host before anything is sent
        if (httpx.URL(url).host or "").lower().rstrip(".") != host:
            raise ProxyError("ambiguous URL (parsers disagree about the host)")
    except httpx.InvalidURL:
        raise ProxyError("malformed URL") from None

    query = parse_qsl(parts.query, keep_blank_values=True)
    for k, v in (params or {}).items():
        query.append((str(k), str(v)))
    caller_query_keys = sorted({k for k, _ in query})
    if cred.kind == "query":
        if any(k == cred.param_name for k, _ in query):
            raise ProxyError(f"query parameter '{cred.param_name}' is reserved for the credential")
        query.append((cred.param_name, cred.value))
    final_url = urlunsplit((scheme, parts.netloc, parts.path, urlencode(query), ""))

    managed = {"bearer": "authorization", "basic": "authorization", "header": cred.header_name.lower()}.get(cred.kind)
    out_headers: dict = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk in FORBIDDEN_REQUEST_HEADERS or lk == managed:
            raise ProxyError(f"header '{k}' is managed by keyvault and cannot be set by the caller")
        out_headers[str(k)] = str(v)
    if cred.kind == "bearer":
        out_headers["Authorization"] = f"Bearer {cred.value}"
    elif cred.kind == "basic":
        out_headers["Authorization"] = "Basic " + base64.b64encode(cred.value.encode()).decode()
    elif cred.kind == "header":
        out_headers[cred.header_name] = cred.value
    if "user-agent" not in {k.lower() for k in out_headers}:
        out_headers["User-Agent"] = f"keyvault/{__version__}"

    return {
        "method": method,
        "url": final_url,
        "host": host,
        "path": parts.path,
        "headers": out_headers,
        "query_keys": caller_query_keys,
    }


# --------------------------------------------------------------------------- send

async def send(
    cred: Credential,
    *,
    method: str,
    url: str,
    headers: dict | None = None,
    params: dict | None = None,
    json_body=None,
    body: str | None = None,
    timeout: float = 30.0,
    max_bytes: int = MAX_BODY_BYTES,
    actor: str = "mcp",
) -> dict:
    max_bytes = max(256, min(int(max_bytes), 2_000_000))
    timeout = max(1.0, min(float(timeout), 120.0))
    try:
        if json_body is not None and body is not None:
            raise ProxyError("pass either json_body or body, not both")
        plan = _plan(cred, method, url, headers, params)
    except ProxyError as e:
        audit({
            "actor": actor, "action": "http_denied", "credential": cred.name,
            "method": str(method).upper(), "reason": str(e),
        })
        raise

    variants = _variants(cred)
    pad = max(len(f.encode("utf-8")) for f in variants)
    read_limit = max_bytes + pad  # read a little extra so a secret straddling the cut can still be redacted
    content = body.encode("utf-8") if body is not None else None
    buf = bytearray()
    hit_limit = False
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            trust_env=plan["host"] not in LOOPBACK,
        ) as client:
            async with client.stream(
                plan["method"], plan["url"], headers=plan["headers"], json=json_body, content=content
            ) as resp:
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) > read_limit:
                        hit_limit = True
                        del buf[read_limit:]
                        break
                status, reason, rheaders = resp.status_code, resp.reason_phrase, resp.headers
    except (httpx.HTTPError, httpx.InvalidURL, OSError) as e:
        msg, _ = redact(f"{type(e).__name__}: {e}", cred, variants)
        audit({
            "actor": actor, "action": "http_error", "credential": cred.name,
            "method": plan["method"], "host": plan["host"], "error": type(e).__name__,
        })
        raise ProxyError(f"request failed: {msg}") from None

    redactions = 0
    out_headers: dict = {}
    for k, v in rheaders.items():
        lk = k.lower()
        if lk in KEEP_HEADERS or lk.startswith(KEEP_PREFIXES):
            out_headers[lk], n = redact(v, cred, variants)
            redactions += n

    ctype = rheaders.get("content-type", "")
    raw = bytes(buf)
    result: dict = {"status": status, "reason": reason, "headers": out_headers}
    if _textual(ctype, raw):
        text, n = redact(raw.decode("utf-8", "replace"), cred, variants)
        redactions += n
        b = text.encode("utf-8")
        cut = max(0, len(b) - pad) if hit_limit else len(b)  # drop the tail where a partial secret could sit
        cut = min(cut, max_bytes)
        result["truncated"] = hit_limit or len(b) > cut
        result["body"] = b[:cut].decode("utf-8", "ignore")
    else:
        result["truncated"] = hit_limit
        result["body"] = None
        result["note"] = f"non-text response ({ctype or 'unknown type'}) omitted"
    if 300 <= status < 400 and "location" in out_headers:
        result["note"] = "redirect not followed; call again with the Location URL (its host must be allowed)"
    if redactions:
        result["redactions"] = redactions

    audit({
        "actor": actor, "action": "http_request", "credential": cred.name, "method": plan["method"],
        "host": plan["host"], "path": plan["path"], "query_keys": plan["query_keys"], "status": status,
    })
    return result
