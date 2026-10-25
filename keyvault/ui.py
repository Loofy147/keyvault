"""Local-only web UI for keyvault.

The UI binds to 127.0.0.1, refuses unexpected Host/Origin headers, uses a per-process CSRF
token, stores no browser-side session or secret values, and never returns credential secrets.
It operates on the same encrypted vault and session cache as the CLI/MCP server.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import vault as V
from .vault import Credential, VaultError

_MAX_REQUEST_BYTES = 1_000_000
_MAX_AUDIT_EVENTS = 200
_AUDIT_FIELDS = {
    "ts", "pid", "actor", "action", "credential", "credentials", "method", "host", "path",
    "query_keys", "status", "allow", "unlock", "session_backend", "ttl_seconds", "command",
    "added", "updated", "skipped", "reason", "error",
}


def _public_credential(c: Credential) -> dict:
    """Owner-facing metadata for the local UI; the secret value is deliberately excluded."""
    return c.agent_view() | {
        "kind": c.kind,
        "header_name": c.header_name,
        "param_name": c.param_name,
        "env_var": c.env_var,
        "notes": c.notes,
        "created": c.created,
        "updated": c.updated,
    }


def _unlocked_vault(path: Path) -> V.Vault:
    key = V.session_key(path)
    if key is None:
        raise V.VaultLocked("Vault is locked. Unlock it to manage credentials.")
    return V.Vault.open_with_key(path, key)


def _read_audit() -> list[dict]:
    path = V.home_dir() / "audit.log"
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-_MAX_AUDIT_EVENTS:]
    except OSError:
        raise VaultError("Audit log could not be read.") from None
    events: list[dict] = []
    for line in lines:
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(event, dict):
            safe = {k: event[k] for k in _AUDIT_FIELDS if k in event}
            events.append(safe)
    return list(reversed(events))


def _ttl_seconds(value) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        raise VaultError("Session duration must be a whole number of seconds.") from None
    if not 60 <= ttl <= 7 * 86400:
        raise VaultError("Session duration must be between 1 minute and 7 days.")
    return ttl


def _strings(value, *, limit: int, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise VaultError(f"{field} must be a list with at most {limit} entries.")
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 300:
            raise VaultError(f"Invalid entry in {field}.")
        if item.strip():
            result.append(item.strip())
    return result


def _make_credential(data: dict, existing: Credential | None = None) -> Credential:
    name = data.get("name")
    secret = data.get("secret", "")
    if not isinstance(name, str):
        raise VaultError("Credential name is required.")
    if existing and name != existing.name:
        raise VaultError("Credential names cannot be changed; create a new credential instead.")
    if not secret and existing is not None:
        secret = existing.value
    if not isinstance(secret, str) or not secret.strip():
        raise VaultError("Enter a secret value for this credential.")
    if len(secret) > 100_000:
        raise VaultError("Secret value is too long.")
    kind = data.get("kind", existing.kind if existing else ("bearer" if data.get("hosts") else "none"))
    if kind not in V.KINDS:
        raise VaultError("Unsupported credential type.")
    hosts = _strings(data.get("hosts", existing.hosts if existing else []), limit=40, field="Hosts")
    methods = _strings(data.get("methods", existing.methods if existing else ["GET", "HEAD"]), limit=6, field="Methods")
    tags = _strings(data.get("tags", existing.tags if existing else []), limit=32, field="Tags")
    provider = data.get("provider", existing.provider if existing else "")
    note = data.get("notes", existing.notes if existing else "")
    header_name = data.get("header_name", existing.header_name if existing else "")
    param_name = data.get("param_name", existing.param_name if existing else "")
    env_var = data.get("env_var", existing.env_var if existing else "")
    for field_name, value, cap in (
        ("Provider", provider, 120), ("Notes", note, 1000), ("Header name", header_name, 100),
        ("Parameter name", param_name, 100), ("Environment variable", env_var, 200),
    ):
        if not isinstance(value, str) or len(value) > cap:
            raise VaultError(f"{field_name} is invalid or too long.")
    c = Credential(
        name=name.strip(), value=secret.strip(), provider=provider.strip(), kind=kind,
        header_name=header_name.strip(), param_name=param_name.strip(), env_var=env_var.strip(),
        hosts=hosts, methods=methods, tags=tags, notes=note.strip(),
        created=existing.created if existing else V.now_iso(),
        updated=V.now_iso(),
    )
    c.validate()
    return c


class KeyvaultUIHandler(BaseHTTPRequestHandler):
    server: "KeyvaultUIServer"

    def log_message(self, fmt, *args):
        # Never write request paths, bodies, or potentially attacker-controlled strings to stderr.
        return

    def _origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def _send(self, status: int, payload: bytes, content_type: str = "application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                         "form-action 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, data: dict):
        self._send(status, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def _check_host(self) -> bool:
        # DNS rebinding protection: never accept a user-controlled hostname as this local service.
        if self.headers.get("Host", "") != f"127.0.0.1:{self.server.server_port}":
            self._json(403, {"error": "Host header rejected. Open the exact localhost URL shown by keyvault."})
            return False
        return True

    def do_GET(self):
        if not self._check_host():
            return
        path = urlsplit(self.path).path
        if path == "/":
            try:
                html = (Path(__file__).with_name("ui.html")).read_text(encoding="utf-8")
            except OSError:
                self._json(500, {"error": "The UI asset is missing. Reinstall keyvault."})
                return
            html = html.replace("__KEYVAULT_CSRF_TOKEN__", self.server.csrf_token)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/status":
            path_vault = V.vault_path()
            exists = path_vault.is_file()
            unlocked = False
            backend = None
            warning = None
            if exists:
                try:
                    backend = V.session_backend_name()
                    unlocked = V.session_key(path_vault) is not None
                except VaultError as exc:
                    warning = str(exc)
            self._json(200, {
                "initialized": exists,
                "unlocked": unlocked,
                "session_backend": backend,
                "environment_passphrase_configured": bool(os.environ.get("KEYVAULT_PASSPHRASE")),
                "warning": warning,
                "credential_count": len(_unlocked_vault(path_vault).creds) if unlocked else None,
            })
            return
        if path == "/api/credentials":
            try:
                vault = _unlocked_vault(V.vault_path())
                self._json(200, {"credentials": [_public_credential(c) for _, c in sorted(vault.creds.items())]})
            except VaultError as exc:
                self._json(423, {"error": str(exc)})
            return
        if path == "/api/audit":
            try:
                self._json(200, {"events": _read_audit()})
            except VaultError as exc:
                self._json(500, {"error": str(exc)})
            return
        self._json(404, {"error": "Not found."})

    def _body(self) -> dict:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("Send JSON with Content-Type: application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request length.") from None
        if not 1 <= length <= _MAX_REQUEST_BYTES:
            raise ValueError("Request body is empty or too large.")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ValueError("Malformed JSON.") from None
        if not isinstance(data, dict):
            raise ValueError("The JSON body must be an object.")
        return data

    def _guard_post(self) -> bool:
        if not self._check_host():
            return False
        if self.headers.get("Origin", "") != self._origin():
            self._json(403, {"error": "Origin rejected."})
            return False
        token = self.headers.get("X-Keyvault-UI", "")
        if not secrets.compare_digest(token, self.server.csrf_token):
            self._json(403, {"error": "Request token rejected. Reload the page and try again."})
            return False
        return True

    def do_POST(self):
        if not self._guard_post():
            return
        path = urlsplit(self.path).path
        try:
            data = self._body()
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        try:
            if path == "/api/init":
                self._init(data)
            elif path == "/api/unlock":
                self._unlock(data)
            elif path == "/api/lock":
                V.end_session(V.vault_path())
                V.audit({"actor": "webui", "action": "lock"})
                self._json(200, {"ok": True, "message": "Session locked."})
            elif path == "/api/credentials/save":
                self._save_credential(data)
            elif path == "/api/credentials/delete":
                self._delete_credential(data)
            else:
                self._json(404, {"error": "Not found."})
        except V.BadPassphrase:
            self.server.record_unlock_failure()
            self._json(401, {"error": "Incorrect passphrase."})
        except (VaultError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            # Deliberately do not serialize exceptions or traceback: they may contain submitted data.
            self._json(500, {"error": "Operation failed. No secret values were returned; inspect the local CLI if needed."})

    def _init(self, data: dict):
        if V.vault_path().exists():
            raise VaultError("Vault already exists.")
        passphrase = data.get("passphrase")
        confirm = data.get("confirm")
        if not isinstance(passphrase, str) or len(passphrase) < 10:
            raise VaultError("Passphrase must contain at least 10 characters.")
        if not secrets.compare_digest(passphrase, confirm if isinstance(confirm, str) else ""):
            raise VaultError("Passphrases do not match.")
        if self.server.unlock_rate_limited():
            raise VaultError("Too many unlock attempts. Wait one minute and try again.")
        ttl = _ttl_seconds(data.get("ttl_seconds", 8 * 3600))
        vault = V.Vault.create(V.vault_path(), passphrase)
        backend = V.start_session(vault, ttl)
        V.audit({"actor": "webui", "action": "init", "ttl_seconds": ttl, "session_backend": V.session_backend_name()})
        self._json(201, {"ok": True, "message": "Vault created and unlocked.", "session_backend": V.session_backend_name()})

    def _unlock(self, data: dict):
        if self.server.unlock_rate_limited():
            raise VaultError("Too many unlock attempts. Wait one minute and try again.")
        passphrase = data.get("passphrase")
        if not isinstance(passphrase, str) or not passphrase:
            raise VaultError("Enter the vault passphrase.")
        vault = V.Vault.open(V.vault_path(), passphrase)
        ttl = _ttl_seconds(data.get("ttl_seconds", 8 * 3600))
        V.start_session(vault, ttl)
        self.server.clear_unlock_failures()
        V.audit({"actor": "webui", "action": "unlock", "ttl_seconds": ttl, "session_backend": V.session_backend_name()})
        self._json(200, {"ok": True, "message": "Vault unlocked.", "session_backend": V.session_backend_name()})

    def _save_credential(self, data: dict):
        vault = _unlocked_vault(V.vault_path())
        name = data.get("name")
        existing = vault.creds.get(name) if isinstance(name, str) else None
        c = _make_credential(data, existing=existing)
        if existing is None and c.name in vault.creds:
            raise VaultError("Credential already exists.")
        vault.put(c)
        V.audit({"actor": "webui", "action": "credential_saved" if existing else "credential_added", "credential": c.name})
        self._json(200, {"ok": True, "message": f"Credential '{c.name}' saved. Secret values are never returned."})

    def _delete_credential(self, data: dict):
        vault = _unlocked_vault(V.vault_path())
        name = data.get("name")
        if not isinstance(name, str) or name not in vault.creds:
            raise VaultError("Credential not found.")
        vault.delete(name)
        V.audit({"actor": "webui", "action": "credential_deleted", "credential": name})
        self._json(200, {"ok": True, "message": f"Credential '{name}' deleted."})


class KeyvaultUIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address=("127.0.0.1", 8765)):
        if address[0] != "127.0.0.1":
            raise ValueError("The keyvault UI may only bind to 127.0.0.1.")
        self.csrf_token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self._unlock_failures: list[float] = []
        super().__init__(address, KeyvaultUIHandler)

    def unlock_rate_limited(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self._unlock_failures = [t for t in self._unlock_failures if now - t < 60]
            return len(self._unlock_failures) >= 5

    def record_unlock_failure(self):
        with self._lock:
            now = time.monotonic()
            self._unlock_failures = [t for t in self._unlock_failures if now - t < 60]
            self._unlock_failures.append(now)

    def clear_unlock_failures(self):
        with self._lock:
            self._unlock_failures.clear()


def run_ui(port: int = 8765, *, open_browser: bool = True):
    """Serve the UI on loopback only. Ctrl-C stops the server."""
    if not 0 <= int(port) <= 65535:
        raise VaultError("Port must be between 0 and 65535.")
    server = KeyvaultUIServer(("127.0.0.1", int(port)))
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"keyvault local UI: {url}")
    print("Local-only server; do not expose this port through a tunnel, reverse proxy, or port forward.")
    print("Press Ctrl-C to stop.")
    if open_browser:
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("keyvault UI stopped.")


if __name__ == "__main__":
    run_ui()
