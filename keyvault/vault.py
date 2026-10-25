"""Encrypted credential store.

On-disk format: JSON envelope {v, kdf{name, log_n, r, p, salt}, nonce, ct}.
Payload = AES-256-GCM under a key derived from the passphrase with scrypt. `v` and `kdf` are bound
as AAD, so editing the KDF parameters in the file makes decryption fail rather than silently
weakening the vault.
"""
from __future__ import annotations

import base64
import dataclasses
import getpass
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT_VERSION = 1
DEFAULT_LOG_N = 17  # scrypt N=2**17, r=8 -> ~128 MiB
MIN_LOG_N = 14
MAX_LOG_N = 20  # refuse vault files that would make us allocate > 1 GiB
KINDS = ("bearer", "header", "query", "basic", "none")
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
HOST_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]+$")
PARAM_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
ENVVAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class VaultError(Exception):
    pass


class BadPassphrase(VaultError):
    pass


class VaultLocked(VaultError):
    pass


# --------------------------------------------------------------------------- paths / io helpers

def home_dir() -> Path:
    return Path(os.environ.get("KEYVAULT_HOME") or (Path.home() / ".keyvault"))


def vault_path() -> Path:
    return home_dir() / "vault.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _ensure_private_dir(p: Path) -> None:
    # Only the mode of directories we create is set; an existing directory is never chmod-ed.
    Path(p).mkdir(mode=0o700, parents=True, exist_ok=True)


def _atomic_write(path: Path, data: bytes, backup: bool = False) -> None:
    path = Path(path)
    _ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")  # 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if backup and path.exists():
            bak = path.with_name(path.name + ".bak")
            bfd = os.open(str(bak), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(bfd, "wb") as g:
                g.write(path.read_bytes())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- credential model

def host_matches(host: str, pattern: str) -> bool:
    """Exact host match, or `*.example.com` (subdomains only, never the apex or look-alikes)."""
    host = host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


@dataclass
class Credential:
    name: str
    value: str
    provider: str = ""
    kind: str = "none"  # bearer | header | query | basic | none (env-only)
    header_name: str = ""
    param_name: str = ""
    env_var: str = ""
    hosts: list = field(default_factory=list)
    methods: list = field(default_factory=lambda: ["GET", "HEAD"])
    tags: list = field(default_factory=list)
    notes: str = ""
    created: str = field(default_factory=now_iso)
    updated: str = field(default_factory=now_iso)

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in names})

    def validate(self) -> None:
        self.hosts = [str(h).strip().lower() for h in self.hosts]
        self.methods = [str(m).strip().upper() for m in self.methods]
        if not NAME_RE.match(self.name or ""):
            raise VaultError("name must be 1-64 chars of a-z 0-9 _ . - and start with a letter or digit")
        if self.kind not in KINDS:
            raise VaultError(f"kind must be one of: {', '.join(KINDS)}")
        if not self.value:
            raise VaultError("secret value is empty")
        if self.kind == "header" and not HEADER_RE.match(self.header_name or ""):
            raise VaultError("kind=header needs --header-name (letters, digits, hyphen)")
        if self.kind == "query" and not PARAM_RE.match(self.param_name or ""):
            raise VaultError("kind=query needs --param-name")
        if self.kind == "basic" and ":" not in self.value:
            raise VaultError("kind=basic expects the secret in the form user:password")
        if self.kind != "none":
            if any(c in self.value for c in "\r\n\x00"):
                raise VaultError("secret contains line breaks or NUL; only env-only (kind=none) credentials may")
            if not self.hosts:
                raise VaultError("HTTP credentials need at least one --host: the only hosts the secret may be sent to")
        if self.env_var and not ENVVAR_RE.match(self.env_var):
            raise VaultError("invalid env var name")
        for h in self.hosts:
            if not HOST_RE.match(h):
                raise VaultError(f"invalid host pattern '{h}' (use api.example.com or *.example.com; no scheme or path)")
        if not self.methods:
            raise VaultError("at least one HTTP method must be enabled")
        bad = [m for m in self.methods if m not in METHODS]
        if bad:
            raise VaultError(f"unsupported method(s): {', '.join(bad)} (allowed: {', '.join(METHODS)})")

    def public(self) -> dict:
        """Everything except the secret (for the owner's CLI)."""
        d = asdict(self)
        d.pop("value")
        return d

    def agent_view(self) -> dict:
        """The minimum an agent needs to choose a credential. No notes, env var names or timestamps."""
        return {
            "name": self.name,
            "provider": self.provider,
            "hosts": list(self.hosts),
            "methods": list(self.methods),
            "tags": list(self.tags),
        }


# --------------------------------------------------------------------------- crypto + storage

def _norm(passphrase: str) -> bytes:
    return unicodedata.normalize("NFKC", passphrase).encode("utf-8")


def _derive(passphrase: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**log_n, r=r, p=p).derive(_norm(passphrase))


def _aad(env: dict) -> bytes:
    return json.dumps({"v": env["v"], "kdf": env["kdf"]}, sort_keys=True, separators=(",", ":")).encode()


def read_envelope(path: Path) -> dict:
    path = Path(path)
    try:
        env = json.loads(path.read_text("utf-8"))
        k = env["kdf"]
        if env["v"] != FORMAT_VERSION or k["name"] != "scrypt":
            raise ValueError("unsupported format")
        _unb64(k["salt"])
        _unb64(env["nonce"])
        _unb64(env["ct"])
        n, r, p = int(k["log_n"]), int(k["r"]), int(k["p"])
    except FileNotFoundError:
        raise VaultError(f"no vault at {path} (run `keyvault init`)") from None
    except (ValueError, KeyError, TypeError, AttributeError):
        raise VaultError(f"{path} is not a valid keyvault file") from None
    if not (MIN_LOG_N <= n <= MAX_LOG_N and 1 <= r <= 16 and 1 <= p <= 4):
        raise VaultError("vault KDF parameters are outside the accepted range")
    return env


class Vault:
    def __init__(self, path: Path, key: bytes, env: dict, creds: dict):
        self.path = Path(path)
        self._key = key
        self._env = env
        self.creds: dict[str, Credential] = creds

    @property
    def key(self) -> bytes:
        return self._key

    @property
    def salt_b64(self) -> str:
        return self._env["kdf"]["salt"]

    # -- construction
    @classmethod
    def create(cls, path: Path, passphrase: str, log_n: int = DEFAULT_LOG_N) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"a vault already exists at {path}")
        if not MIN_LOG_N <= log_n <= MAX_LOG_N:
            raise VaultError(f"kdf log_n must be between {MIN_LOG_N} and {MAX_LOG_N}")
        v = cls(path, b"", {}, {})
        v._rekey(passphrase, log_n)
        v.save()
        return v

    @classmethod
    def open(cls, path: Path, passphrase: str) -> "Vault":
        env = read_envelope(path)
        k = env["kdf"]
        key = _derive(passphrase, _unb64(k["salt"]), int(k["log_n"]), int(k["r"]), int(k["p"]))
        return cls._decrypt(path, key, env)

    @classmethod
    def open_with_key(cls, path: Path, key: bytes) -> "Vault":
        return cls._decrypt(path, key, read_envelope(path))

    @classmethod
    def _decrypt(cls, path: Path, key: bytes, env: dict) -> "Vault":
        try:
            pt = AESGCM(key).decrypt(_unb64(env["nonce"]), _unb64(env["ct"]), _aad(env))
        except InvalidTag:
            raise BadPassphrase("wrong passphrase, or the vault file was modified") from None
        try:
            data = json.loads(pt)
            creds = {n: Credential.from_dict(c) for n, c in data["credentials"].items()}
        except (ValueError, KeyError, TypeError, AttributeError):
            raise VaultError("vault payload is malformed") from None
        return cls(path, key, env, creds)

    # -- mutation
    def _rekey(self, passphrase: str, log_n: int) -> None:
        salt = os.urandom(16)
        self._env = {"v": FORMAT_VERSION, "kdf": {"name": "scrypt", "log_n": log_n, "r": 8, "p": 1, "salt": _b64(salt)}}
        self._key = _derive(passphrase, salt, log_n, 8, 1)

    def save(self) -> None:
        payload = json.dumps(
            {"credentials": {n: asdict(c) for n, c in sorted(self.creds.items())}}, sort_keys=True
        ).encode()
        env = {"v": self._env["v"], "kdf": self._env["kdf"]}
        nonce = os.urandom(12)  # fresh nonce on every write
        env["nonce"] = _b64(nonce)
        env["ct"] = _b64(AESGCM(self._key).encrypt(nonce, payload, _aad(env)))
        _atomic_write(self.path, json.dumps(env, indent=2).encode(), backup=True)
        self._env = env

    def put(self, cred: Credential) -> None:
        self.put_many([cred])

    def put_many(self, creds: list) -> None:
        for c in creds:
            c.validate()
        for c in creds:
            c.updated = now_iso()
            self.creds[c.name] = c
        self.save()

    def delete(self, name: str) -> None:
        if name not in self.creds:
            raise VaultError(f"no credential named '{name}'")
        del self.creds[name]
        self.save()

    def change_passphrase(self, new_passphrase: str) -> None:
        self._rekey(new_passphrase, int(self._env["kdf"]["log_n"]))
        self.save()
        # The backup written by save() is encrypted under the OLD key; drop it so the old passphrase stops working.
        self.path.with_name(self.path.name + ".bak").unlink(missing_ok=True)


# --------------------------------------------------------------------------- unlock session

SESSION_BACKEND_ENV = "KEYVAULT_SESSION_BACKEND"
SESSION_SERVICE = "keyvault.session.v1"
SESSION_TTL_MAX = 7 * 86400


def session_backend_name() -> str:
    """Return the configured session store. Native OS storage is the secure default.

    The file backend is an explicit compatibility escape hatch for headless systems without a
    native credential service; it must never be selected implicitly.
    """
    name = os.environ.get(SESSION_BACKEND_ENV, "keychain").strip().lower()
    if name not in {"keychain", "file"}:
        raise VaultError(f"{SESSION_BACKEND_ENV} must be 'keychain' or 'file'")
    return name


def session_file(vpath: Path) -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    d = Path(base) / "keyvault" if base else home_dir()
    tag = hashlib.sha256(str(Path(vpath).resolve()).encode()).hexdigest()[:12]
    return d / f"session-{tag}.json"


def _session_keychain_id(vpath: Path) -> tuple[str, str]:
    # Do not put the vault path itself into OS keychain labels or usernames.
    tag = hashlib.sha256(str(Path(vpath).resolve()).encode()).hexdigest()
    return SESSION_SERVICE, tag


def _native_keychain_backend():
    """Instantiate a known OS keychain backend, bypassing keyring auto-selection/fallbacks.

    `keyring.get_keyring()` may select third-party, file, null, or chained backends. keyvault
    intentionally does not accept those for its default security-sensitive session cache.
    """
    try:
        if sys.platform == "darwin":
            from keyring.backends.macOS import Keyring
        elif os.name == "nt":
            from keyring.backends.Windows import WinVaultKeyring as Keyring
        elif sys.platform.startswith("linux"):
            from keyring.backends.SecretService import Keyring
        else:
            raise VaultError(f"native OS keychain sessions are unsupported on {sys.platform!r}")
        backend = Keyring()
        priority = backend.priority  # validates dependencies and service availability
        if not isinstance(priority, (int, float)) or priority <= 0:
            raise RuntimeError("backend is unavailable")
        return backend
    except VaultError:
        raise
    except Exception as exc:
        # Exception text from third-party backends is deliberately not exposed in CLI/MCP output.
        raise VaultError(
            "native OS keychain is unavailable; unlock the platform credential service or "
            f"explicitly opt into the less-secure file cache with {SESSION_BACKEND_ENV}=file "
            f"(backend error: {type(exc).__name__})"
        ) from None


def _keychain_call(backend, action: str, fn):
    try:
        return fn()
    except Exception as exc:
        raise VaultError(
            f"native OS keychain {action} failed; no file-cache fallback was used "
            f"(backend error: {type(exc).__name__})"
        ) from None


def _unlink(p: Path) -> None:
    try:
        Path(p).unlink()
    except OSError:
        pass


def _encode_session(vault: Vault, ttl: int) -> str:
    if not isinstance(ttl, int) or not 1 <= ttl <= SESSION_TTL_MAX:
        raise VaultError("session TTL must be between 1 second and 7 days")
    payload = {"v": 1, "key": _b64(vault.key), "salt": vault.salt_b64, "expires": time.time() + ttl}
    return json.dumps(payload, separators=(",", ":"))


def start_session(vault: Vault, ttl: int) -> Path | str:
    """Cache the derived key in the native OS keychain; use a 0600 file only by explicit opt-in."""
    raw = _encode_session(vault, ttl)
    if session_backend_name() == "file":
        f = session_file(vault.path)
        _atomic_write(f, raw.encode("utf-8"))
        return f

    backend = _native_keychain_backend()
    service, username = _session_keychain_id(vault.path)
    _keychain_call(backend, "write", lambda: backend.set_password(service, username, raw))
    # Remove an old pre-keychain cache only after the secure write succeeded.
    _unlink(session_file(vault.path))
    return "native OS keychain"


def _delete_keychain_session(vpath: Path, *, missing_ok: bool = True) -> None:
    backend = _native_keychain_backend()
    service, username = _session_keychain_id(vpath)
    raw = _keychain_call(backend, "read", lambda: backend.get_password(service, username))
    if raw is None:
        if not missing_ok:
            raise VaultError("no session exists in the native OS keychain")
        return
    _keychain_call(backend, "delete", lambda: backend.delete_password(service, username))


def _discard_session(vpath: Path, backend_name: str) -> None:
    if backend_name == "file":
        _unlink(session_file(vpath))
        return
    # Invalid/expired entries are unusable even if deleting the stale item fails.
    try:
        _delete_keychain_session(vpath)
    except VaultError:
        pass


def session_key(vpath: Path) -> bytes | None:
    backend_name = session_backend_name()
    if backend_name == "file":
        f = session_file(vpath)
        try:
            raw = f.read_text("utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise VaultError(f"could not read the session file ({type(exc).__name__})") from None
    else:
        backend = _native_keychain_backend()
        service, username = _session_keychain_id(vpath)
        raw = _keychain_call(backend, "read", lambda: backend.get_password(service, username))
        if raw is None:
            return None

    try:
        d = json.loads(raw)
        if d.get("v", 1) != 1:
            raise ValueError("unsupported session version")
        expires, salt, key = float(d["expires"]), d["salt"], _unb64(d["key"])
        if len(key) != 32:
            raise ValueError("invalid key length")
    except (ValueError, KeyError, TypeError, AttributeError):
        _discard_session(vpath, backend_name)
        return None
    if expires <= time.time():
        _discard_session(vpath, backend_name)
        return None
    try:
        if salt != read_envelope(vpath)["kdf"]["salt"]:  # vault re-keyed or replaced
            _discard_session(vpath, backend_name)
            return None
    except VaultError:
        return None
    return key


def end_session(vpath: Path) -> None:
    """Invalidate the configured session. Keychain deletion failures are reported, not hidden."""
    backend_name = session_backend_name()
    if backend_name == "file":
        _unlink(session_file(vpath))
        return
    try:
        _delete_keychain_session(vpath)
    finally:
        # Remove any legacy file cache so it cannot become active after a backend switch.
        _unlink(session_file(vpath))

def unlock(path: Path, *, interactive: bool) -> tuple[Vault, str]:
    """Open the vault. Order: live session -> KEYVAULT_PASSPHRASE -> prompt (only if interactive).

    Returns (vault, source) with source in {"session", "env", "prompt"}.
    """
    path = Path(path)
    if not path.exists():
        raise VaultError(f"no vault at {path} (run `keyvault init`)")
    # Validate the configuration outside the recovery path: an invalid backend setting is not
    # equivalent to an unavailable OS keychain and must never be silently ignored.
    session_backend_name()
    try:
        k = session_key(path)
    except VaultError:
        # A user-supplied passphrase or interactive prompt is an explicit alternative authority;
        # non-interactive callers must not silently bypass an unavailable session store.
        if not interactive and os.environ.get("KEYVAULT_PASSPHRASE") is None:
            raise
        k = None
    if k is not None:
        try:
            return Vault.open_with_key(path, k), "session"
        except BadPassphrase:
            end_session(path)
    pw = os.environ.get("KEYVAULT_PASSPHRASE")
    source = "env"
    if pw is None and interactive:
        pw = getpass.getpass("Vault passphrase: ")
        source = "prompt"
    if pw is None:
        raise VaultLocked("vault is locked: run `keyvault unlock` (or set KEYVAULT_PASSPHRASE for unattended use)")
    return Vault.open(path, pw), source


def _sig(path: Path) -> tuple:
    try:
        st = Path(path).stat()
    except OSError:
        raise VaultError(f"vault file {path} is missing") from None
    return (st.st_ino, st.st_mtime_ns, st.st_size)


class VaultHandle:
    """Long-lived accessor for servers: picks up edits/rotations and honours session expiry."""

    def __init__(self, path: Path, vault: Vault, source: str):
        self.path = Path(path)
        self._vault = vault
        self.source = source
        self._sig = _sig(self.path)

    def current(self) -> Vault:
        key = self._vault.key
        if self.source == "session":
            k = session_key(self.path)
            if k is None:
                raise VaultLocked("vault is locked (session expired or `keyvault lock` was run); run `keyvault unlock`")
            key = k
        sig = _sig(self.path)
        if key != self._vault.key or sig != self._sig:
            try:
                self._vault = Vault.open_with_key(self.path, key)
            except BadPassphrase:
                raise VaultLocked("vault key changed (passphrase rotated?); restart this server or run `keyvault unlock`") from None
            self._sig = sig
        return self._vault


# --------------------------------------------------------------------------- audit log

def audit(event: dict) -> None:
    """Append one JSON line. Callers must never pass secret values; fail-open with a warning."""
    try:
        p = home_dir() / "audit.log"
        _ensure_private_dir(p.parent)
        fd = os.open(str(p), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now_iso(), "pid": os.getpid(), **event}, sort_keys=True) + "\n")
    except OSError as e:
        print(f"keyvault: warning: could not write audit log: {e}", file=sys.stderr)
