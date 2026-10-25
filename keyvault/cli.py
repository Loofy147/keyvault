"""keyvault command line."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from pathlib import Path

from . import __version__
from . import vault as V
from .vault import Credential, VaultError


def _die(msg: str, code: int = 1):
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _open_vault(interactive: bool | None = None) -> V.Vault:
    if interactive is None:
        interactive = sys.stdin.isatty()
    vault, _source = V.unlock(V.vault_path(), interactive=interactive)
    return vault


def _csv(s: str) -> list:
    return [x.strip() for x in s.split(",") if x.strip()]


def _parse_ttl(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd]?)", s.strip().lower())
    if not m:
        _die("ttl looks like 30m, 8h or 1d")
    n = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 1 <= n <= 7 * 86400:
        _die("ttl must be between 1s and 7d")
    return n


def _new_passphrase(env_name: str) -> str:
    pw = os.environ.get(env_name)
    if pw is None:
        if not sys.stdin.isatty():
            _die(f"no TTY; set {env_name} for non-interactive use")
        pw = getpass.getpass("New passphrase: ")
        if pw != getpass.getpass("Repeat passphrase: "):
            _die("passphrases do not match")
    if len(pw) < 10:
        _die("passphrase must be at least 10 characters")
    return pw


def _read_value(name: str, from_stdin: bool) -> str:
    if from_stdin:
        v = sys.stdin.read()
    elif sys.stdin.isatty():
        v = getpass.getpass(f"Secret for '{name}' (input hidden): ")
    else:
        _die("no TTY: pipe the secret in and pass --value-stdin (secrets are never accepted as arguments)")
    v = v.strip()
    if not v:
        _die("empty secret")
    return v


def _get(vault: V.Vault, name: str) -> Credential:
    c = vault.creds.get(name)
    if c is None:
        _die(f"no credential named '{name}'")
    return c


# --------------------------------------------------------------------------- .env parsing

def parse_dotenv(text: str) -> list:
    """Single-line KEY=VALUE entries; supports `export`, quotes, escapes in double quotes, inline comments."""
    out: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, val = line.partition("=")
        key = key.strip()
        if not sep or not V.ENVVAR_RE.match(key):
            continue
        val = val.strip()
        if val[:1] in ("'", '"'):
            q, buf, i = val[0], [], 1
            while i < len(val):
                ch = val[i]
                if q == '"' and ch == "\\" and i + 1 < len(val):
                    buf.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(val[i + 1], "\\" + val[i + 1]))
                    i += 2
                    continue
                if ch == q:
                    break
                buf.append(ch)
                i += 1
            val = "".join(buf)
        else:
            m = re.search(r"\s#", val)
            if m:
                val = val[: m.start()]
            val = val.strip()
        if val:
            out[key] = val
    return list(out.items())


def _name_from_var(var: str) -> str:
    return re.sub(r"[^a-z0-9_.-]", "_", var.lower()).lstrip("_.-")


# --------------------------------------------------------------------------- commands

def cmd_init(a):
    path = V.vault_path()
    if path.exists():
        _die(f"a vault already exists at {path}")
    pw = _new_passphrase("KEYVAULT_PASSPHRASE")
    t0 = time.perf_counter()
    V.Vault.create(path, pw, log_n=a.kdf_log_n)
    print(f"created {path} (scrypt N=2^{a.kdf_log_n}; key derivation took {time.perf_counter() - t0:.2f}s)")
    return 0


def cmd_unlock(a):
    path = V.vault_path()
    pw = os.environ.get("KEYVAULT_PASSPHRASE")
    if pw is None:
        if not sys.stdin.isatty():
            _die("no TTY; set KEYVAULT_PASSPHRASE for non-interactive unlock")
        pw = getpass.getpass("Vault passphrase: ")
    vault = V.Vault.open(path, pw)
    ttl = _parse_ttl(a.ttl)
    location = V.start_session(vault, ttl)
    backend = V.session_backend_name()
    V.audit({"actor": "cli", "action": "unlock", "ttl_seconds": ttl, "session_backend": backend})
    if isinstance(location, Path):
        stored_at = f"{location} (mode 0600)"
    else:
        stored_at = location
    print(f"unlocked for {a.ttl}. The derived key is cached in {stored_at} until it expires or you run `keyvault lock`.")
    return 0


def cmd_lock(a):
    V.end_session(V.vault_path())
    V.audit({"actor": "cli", "action": "lock"})
    print("locked. `serve` processes that were started from an unlock session stop answering immediately; "
          "ones started with KEYVAULT_PASSPHRASE keep their key until they exit.")
    return 0


def cmd_add(a):
    vault = _open_vault()
    if a.name in vault.creds:
        _die(f"'{a.name}' already exists (use `keyvault edit {a.name}`)")
    value = _read_value(a.name, a.value_stdin)
    c = Credential(
        name=a.name,
        value=value,
        provider=a.provider or "",
        kind=a.kind or ("bearer" if a.host else "none"),
        header_name=a.header_name or "",
        param_name=a.param_name or "",
        env_var=a.env_var or "",
        hosts=a.host or [],
        methods=_csv(a.methods) if a.methods else ["GET", "HEAD"],
        tags=a.tag or [],
        notes=a.note or "",
    )
    vault.put(c)
    V.audit({"actor": "cli", "action": "add", "credential": c.name})
    print(f"added '{c.name}' (kind={c.kind})")
    if c.kind != "none" and c.methods == ["GET", "HEAD"]:
        print("note: HTTP use is read-only (GET/HEAD) by default; enable writes with --methods GET,POST,...")
    return 0


def cmd_edit(a):
    vault = _open_vault()
    c = _get(vault, a.name)
    for attr, val in (
        ("provider", a.provider), ("kind", a.kind), ("header_name", a.header_name),
        ("param_name", a.param_name), ("env_var", a.env_var), ("notes", a.note),
    ):
        if val is not None:
            setattr(c, attr, val)
    if a.host is not None:
        c.hosts = a.host
    if a.methods is not None:
        c.methods = _csv(a.methods)
    if a.tag is not None:
        c.tags = a.tag
    if a.rotate:
        c.value = _read_value(a.name, a.value_stdin)
    vault.put(c)
    V.audit({"actor": "cli", "action": "rotate" if a.rotate else "edit", "credential": c.name})
    print(f"updated '{c.name}'")
    return 0


def cmd_list(a):
    vault = _open_vault()
    creds = sorted(vault.creds.values(), key=lambda c: c.name)
    if a.json:
        print(json.dumps([c.public() for c in creds], indent=2))
        return 0
    if not creds:
        print("(empty) - add one with `keyvault add NAME --value-stdin ...`")
        return 0
    rows = [("NAME", "PROVIDER", "KIND", "HOSTS", "METHODS", "ENV", "TAGS")]
    for c in creds:
        rows.append((
            c.name, c.provider or "-", c.kind, ",".join(c.hosts) or "-",
            ",".join(c.methods) if c.kind != "none" else "-", c.env_var or "-", ",".join(c.tags) or "-",
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(x.ljust(w) for x, w in zip(r, widths)).rstrip())
    return 0


def cmd_show(a):
    print(json.dumps(_get(_open_vault(), a.name).public(), indent=2))
    return 0


def cmd_get(a):
    c = _get(_open_vault(), a.name)
    V.audit({"actor": "cli", "action": "get", "credential": a.name})
    print(c.value)
    return 0


def cmd_rm(a):
    vault = _open_vault()
    _get(vault, a.name)
    if not a.yes:
        if not sys.stdin.isatty():
            _die("refusing to delete without --yes when not on a TTY")
        if input(f"delete '{a.name}'? [y/N] ").strip().lower() != "y":
            print("aborted")
            return 1
    vault.delete(a.name)
    V.audit({"actor": "cli", "action": "rm", "credential": a.name})
    print(f"removed '{a.name}' (the previous vault version stays encrypted in vault.json.bak until the next change)")
    return 0


def cmd_import_env(a):
    path = Path(a.file)
    try:
        pairs = parse_dotenv(path.read_text(encoding="utf-8"))
    except OSError as e:
        _die(f"cannot read {path}: {e}")
    plan = [(_name_from_var(var), var, val) for var, val in pairs]
    if not plan:
        print("no KEY=VALUE entries found")
        return 0
    if a.dry_run:
        for name, var, _ in plan:
            print(f"would import {var} -> {name}")
        return 0
    vault = _open_vault()
    to_put, added, updated, skipped = [], 0, 0, 0
    for name, var, val in plan:
        existing = vault.creds.get(name)
        if existing is not None and not a.overwrite:
            print(f"skip    {name} (already exists; --overwrite replaces the value and keeps its settings)")
            skipped += 1
            continue
        c = existing or Credential(name=name, value=val, kind="none", env_var=var)
        c.value = val
        try:
            c.validate()
        except VaultError as e:
            print(f"skip    {var}: {e}")
            skipped += 1
            continue
        to_put.append(c)
        if existing is None:
            added += 1
            print(f"add     {name}  (env var {var})")
        else:
            updated += 1
            print(f"update  {name}")
    if to_put:
        vault.put_many(to_put)
    V.audit({"actor": "cli", "action": "import-env", "added": added, "updated": updated, "skipped": skipped})
    print(f"\n{added} added, {updated} updated, {skipped} skipped.")
    print("New entries are env-only (kind=none) until you give them HTTP settings, e.g.:")
    print("  keyvault edit NAME --kind bearer --host api.example.com")
    print(f"{path} still holds these secrets in plaintext; delete it once you have checked the import.")
    return 0


def cmd_run(a):
    if not a.rest:
        _die("usage: keyvault run [CRED ...] [-e VAR=CRED ...] -- COMMAND [ARGS...]")
    vault = _open_vault()
    env = dict(os.environ)
    env.pop("KEYVAULT_PASSPHRASE", None)  # never hand the master passphrase to the child
    used = []
    for n in a.creds:
        c = _get(vault, n)
        if not c.env_var:
            _die(f"'{n}' has no env var; use -e VAR={n} or `keyvault edit {n} --env-var VAR`")
        env[c.env_var] = c.value
        used.append(n)
    for spec in a.env:
        var, sep, n = spec.partition("=")
        if not sep or not V.ENVVAR_RE.match(var):
            _die(f"bad -e value '{spec}' (expected VAR=CREDENTIAL)")
        env[var] = _get(vault, n).value
        used.append(n)
    V.audit({"actor": "cli", "action": "run", "credentials": sorted(set(used)), "command": os.path.basename(a.rest[0])})
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "posix":
        try:
            os.execvpe(a.rest[0], a.rest, env)  # replaces this process: stdio passes straight through
        except FileNotFoundError:
            _die(f"command not found: {a.rest[0]}", 127)
        except OSError as e:
            _die(str(e), 126)
    import subprocess  # non-POSIX fallback (untested)

    try:
        return subprocess.call(a.rest, env=env)
    except FileNotFoundError:
        _die(f"command not found: {a.rest[0]}", 127)


def cmd_serve(a):
    path = V.vault_path()
    vault, source = V.unlock(path, interactive=False)  # never prompt: stdin is the MCP channel
    allow = set(_csv(a.allow)) if a.allow else None
    if allow:
        missing = sorted(allow - set(vault.creds))
        if missing:
            _die(f"--allow names not in the vault: {', '.join(missing)}")
    handle = V.VaultHandle(path, vault, source)
    from .mcp_server import build_server

    V.audit({"actor": "cli", "action": "serve", "allow": sorted(allow) if allow else "all", "unlock": source})
    print(f"keyvault MCP server on stdio (unlock={source}, scope={'all HTTP credentials' if allow is None else ','.join(sorted(allow))})",
          file=sys.stderr)
    build_server(handle, allow, a.max_bytes).run()
    return 0


def cmd_snippet(a):
    if a.what == "serve":
        args = ["-m", "keyvault", "serve"] + (["--allow", a.allow] if a.allow else [])
        name = a.name or "keyvault"
    else:
        if not a.rest:
            _die("usage: keyvault snippet run [CRED ...] [-e VAR=CRED ...] -- COMMAND [ARGS...]")
        args = ["-m", "keyvault", "run", *a.creds]
        for spec in a.env:
            args += ["-e", spec]
        args += ["--", *a.rest]
        name = a.name or (a.creds[0] if a.creds else Path(a.rest[0]).name)
    entry: dict = {"command": sys.executable, "args": args}
    child_env = {}
    if os.environ.get("KEYVAULT_HOME"):
        child_env["KEYVAULT_HOME"] = os.environ["KEYVAULT_HOME"]
    if os.environ.get(V.SESSION_BACKEND_ENV):
        child_env[V.SESSION_BACKEND_ENV] = V.session_backend_name()
    if child_env:
        entry["env"] = child_env
    print(json.dumps({"mcpServers": {name: entry}}, indent=2))
    print("# contains no secrets; merge into the mcpServers section of your MCP client config", file=sys.stderr)
    return 0


def cmd_audit(a):
    p = V.home_dir() / "audit.log"
    if not p.exists():
        print("(no audit log yet)")
        return 0
    for line in p.read_text(encoding="utf-8").splitlines()[-a.n:]:
        print(line)
    return 0


def cmd_passwd(a):
    vault = _open_vault()
    vault.change_passphrase(_new_passphrase("KEYVAULT_NEW_PASSPHRASE"))
    V.end_session(vault.path)
    V.audit({"actor": "cli", "action": "passwd"})
    print("passphrase changed; the old-key backup was removed and the unlock session cleared")
    return 0


# --------------------------------------------------------------------------- parser

def _cred_flags(sp, editing: bool) -> None:
    sp.add_argument("--provider")
    sp.add_argument("--kind", choices=V.KINDS,
                    help="how the secret is attached to HTTP requests (default: bearer if --host is given, else none = env-only)")
    sp.add_argument("--header-name", help="header for kind=header, e.g. x-api-key")
    sp.add_argument("--param-name", help="query parameter for kind=query")
    sp.add_argument("--env-var", help="env var name used by `keyvault run`")
    sp.add_argument("--host", action="append",
                    help="host the secret may be sent to (repeatable; *.example.com allowed)" + ("; replaces the list" if editing else ""))
    sp.add_argument("--methods", help="comma list of enabled HTTP methods (default GET,HEAD)")
    sp.add_argument("--tag", action="append")
    sp.add_argument("--note", help="private note, never shown to agents")
    sp.add_argument("--value-stdin", action="store_true", help="read the secret from stdin instead of a hidden prompt")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keyvault",
                                description="Local encrypted vault for API keys and tokens, usable by MCP servers and agents.")
    p.add_argument("--version", action="version", version=f"keyvault {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    sp = sub.add_parser("init", help="create the vault")
    sp.add_argument("--kdf-log-n", type=int, default=V.DEFAULT_LOG_N,
                    help=f"scrypt cost N=2^value (default {V.DEFAULT_LOG_N}, minimum {V.MIN_LOG_N})")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("unlock", help="cache the derived key so non-interactive clients can use the vault")
    sp.add_argument("--ttl", default="8h", help="30m, 8h, 1d ... (max 7d; default 8h)")
    sp.set_defaults(func=cmd_unlock)

    sp = sub.add_parser("lock", help="forget the cached key")
    sp.set_defaults(func=cmd_lock)

    sp = sub.add_parser("add", help="add a credential (secret from hidden prompt or stdin, never argv)")
    sp.add_argument("name")
    _cred_flags(sp, editing=False)
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("edit", help="change a credential's settings; --rotate replaces the secret")
    sp.add_argument("name")
    _cred_flags(sp, editing=True)
    sp.add_argument("--rotate", action="store_true", help="read a new secret value")
    sp.set_defaults(func=cmd_edit)

    sp = sub.add_parser("list", help="list credentials (never prints secrets)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("show", help="show one credential's settings (never prints the secret)")
    sp.add_argument("name")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("get", help="print a secret to stdout (audited)")
    sp.add_argument("name")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("rm", help="delete a credential")
    sp.add_argument("name")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=cmd_rm)

    sp = sub.add_parser("import-env", help="gather credentials from a .env file (prints names only)")
    sp.add_argument("file")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--overwrite", action="store_true", help="replace the value of existing credentials, keeping their settings")
    sp.set_defaults(func=cmd_import_env)

    sp = sub.add_parser("run", help="run a command with credentials injected as env vars:  run [CRED ...] [-e VAR=CRED ...] -- CMD ...")
    sp.add_argument("creds", nargs="*")
    sp.add_argument("-e", "--env", action="append", default=[], metavar="VAR=CRED")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("serve", help="run the MCP server on stdio")
    sp.add_argument("--allow", help="comma-separated credential names this server may use (default: all HTTP credentials)")
    sp.add_argument("--max-bytes", type=int, default=100_000, help="response body cap")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("snippet", help="print an mcpServers JSON entry for a client config")
    ssub = sp.add_subparsers(dest="what", required=True, metavar="serve|run")
    s1 = ssub.add_parser("serve", help="entry for the keyvault MCP server")
    s1.add_argument("--allow")
    s1.add_argument("--name")
    s2 = ssub.add_parser("run", help="entry that wraps a third-party MCP server:  snippet run [CRED ...] -- CMD ...")
    s2.add_argument("creds", nargs="*")
    s2.add_argument("-e", "--env", action="append", default=[], metavar="VAR=CRED")
    s2.add_argument("--name")
    sp.set_defaults(func=cmd_snippet)

    sp = sub.add_parser("audit", help="show recent audit-log lines")
    sp.add_argument("-n", type=int, default=20)
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("passwd", help="change the vault passphrase")
    sp.set_defaults(func=cmd_passwd)
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rest: list = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    args.rest = rest
    try:
        return args.func(args) or 0
    except VaultError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
