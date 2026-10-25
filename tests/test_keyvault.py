import asyncio
import base64
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from keyvault import vault as V
from keyvault.cli import parse_dotenv
from keyvault.proxy import ProxyError, send

PW = "correct horse battery staple"
SECRET = "sk-live-4f9a1c7e22b84d0f9a6e3b51c8d7a210"
OTHER = "other-secret-0123456789abcdef"
LOG_N = 14  # cheap scrypt for tests; the production default is 17


# --------------------------------------------------------------------------- fixtures / helpers

@pytest.fixture
def kv(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYVAULT_HOME", str(tmp_path / "kv"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("KEYVAULT_ALLOW_LOOPBACK_HTTP", "1")
    # The suite's subprocess tests use an explicit file backend so they do not depend on
    # the CI runner having a desktop keychain/Secret Service daemon.
    monkeypatch.setenv("KEYVAULT_SESSION_BACKEND", "file")
    monkeypatch.delenv("KEYVAULT_PASSPHRASE", raising=False)
    return tmp_path


def child_env(tmp_path, passphrase=None):
    env = dict(os.environ)
    env.update(
        KEYVAULT_HOME=str(tmp_path / "kv"),
        XDG_RUNTIME_DIR=str(tmp_path / "run"),
        KEYVAULT_ALLOW_LOOPBACK_HTTP="1",
        KEYVAULT_SESSION_BACKEND="file",
        NO_PROXY="127.0.0.1,localhost",
    )
    env.pop("KEYVAULT_PASSPHRASE", None)
    if passphrase is not None:
        env["KEYVAULT_PASSPHRASE"] = passphrase
    return env


def run_cli(tmp_path, *args, input=None, passphrase=PW):
    return subprocess.run(
        [sys.executable, "-m", "keyvault", *args],
        env=child_env(tmp_path, passphrase),
        input=input,
        stdin=None if input is not None else subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _go(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        rec = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
        }
        self.server.seen.append(rec)
        route = self.path.split("?")[0]
        auth = self.headers.get("authorization", "")
        if route == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if route == "/straddle":
            payload, ctype = ("A" * self.server.straddle_at + SECRET + "B" * 3000).encode(), "text/plain"
        elif route == "/many":
            payload = ((SECRET + ".") * 12 + "A" * self.server.straddle_at + SECRET + "B" * 3000).encode()
            ctype = "text/plain"
        elif route == "/binary":
            payload, ctype = bytes(range(256)), "application/octet-stream"
        else:
            payload, ctype = json.dumps(rec).encode(), "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Link", f"<http://example.test/?k={auth}>")  # echoes the secret in an allowed header
        self.send_header("X-Secret-Echo", auth)  # not on the response allowlist: must be dropped
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _go


def _start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.seen, srv.redirect_to, srv.straddle_at = [], "", 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def server(kv):
    srv, base = _start()
    yield srv, base
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def server2(kv):
    srv, base = _start()
    yield srv, base
    srv.shutdown()
    srv.server_close()


def mk(kind="bearer", value=SECRET, **kw):
    kw.setdefault("hosts", ["127.0.0.1"])
    c = V.Credential(name="local", value=value, kind=kind, **kw)
    c.validate()
    return c


def go(cred, **kw):
    return asyncio.run(send(cred, **kw))


# --------------------------------------------------------------------------- vault: storage + crypto

def test_file_properties(kv):
    path = V.vault_path()
    v = V.Vault.create(path, PW, log_n=LOG_N)
    v.put(V.Credential(name="gh", value=SECRET, kind="bearer", hosts=["api.github.com"]))
    raw1 = path.read_bytes()
    assert SECRET.encode() not in raw1 and base64.b64encode(SECRET.encode()) not in raw1
    assert (path.stat().st_mode & 0o777) == 0o600
    nonce1 = json.loads(raw1)["nonce"]

    v.put(V.Credential(name="x", value="another-secret-value", kind="none"))
    assert json.loads(path.read_bytes())["nonce"] != nonce1  # fresh nonce per write
    bak = path.with_name("vault.json.bak")
    assert bak.exists() and (bak.stat().st_mode & 0o777) == 0o600
    assert not list(path.parent.glob("*.tmp"))  # atomic write leaves no temp files

    v2 = V.Vault.open(path, PW)
    assert v2.creds["gh"].value == SECRET and v2.creds["gh"].hosts == ["api.github.com"]
    with pytest.raises(V.VaultError):
        V.Vault.create(path, PW, log_n=LOG_N)  # never overwrites an existing vault
    with pytest.raises(V.VaultError):
        V.Vault.create(path.with_name("other.json"), PW, log_n=10)  # KDF floor


def test_wrong_passphrase_and_tamper(kv):
    path = V.vault_path()
    v = V.Vault.create(path, PW, log_n=LOG_N)
    v.put(V.Credential(name="a", value=SECRET, kind="none"))
    good = path.read_text()

    with pytest.raises(V.BadPassphrase):
        V.Vault.open(path, "definitely the wrong passphrase")

    def corrupt(mutate):
        env = json.loads(good)
        mutate(env)
        path.write_text(json.dumps(env))

    def flip_ct(env):
        ct = bytearray(base64.b64decode(env["ct"]))
        ct[5] ^= 1
        env["ct"] = base64.b64encode(bytes(ct)).decode()

    corrupt(flip_ct)
    with pytest.raises(V.BadPassphrase):
        V.Vault.open(path, PW)

    corrupt(lambda env: env["kdf"].update(r=9))  # changes the derived key
    with pytest.raises(V.BadPassphrase):
        V.Vault.open(path, PW)

    corrupt(lambda env: env["kdf"].update(note="x"))  # key unchanged; only the AAD differs
    with pytest.raises(V.BadPassphrase):
        V.Vault.open(path, PW)

    corrupt(lambda env: env["kdf"].update(log_n=25))  # absurd cost: refused before any derivation
    with pytest.raises(V.VaultError) as ei:
        V.Vault.open(path, PW)
    assert not isinstance(ei.value, V.BadPassphrase)

    path.write_text("not json at all")
    with pytest.raises(V.VaultError):
        V.Vault.open(path, PW)

    path.write_text(good)
    assert V.Vault.open(path, PW).creds["a"].value == SECRET


def test_session_unlock_sources_and_expiry(kv, monkeypatch):
    path = V.vault_path()
    v = V.Vault.create(path, PW, log_n=LOG_N)

    with pytest.raises(V.VaultLocked):  # no session, no env, non-interactive
        V.unlock(path, interactive=False)

    monkeypatch.setenv("KEYVAULT_PASSPHRASE", PW)
    assert V.unlock(path, interactive=False)[1] == "env"
    monkeypatch.delenv("KEYVAULT_PASSPHRASE")

    sf = V.start_session(v, ttl=600)
    assert (sf.stat().st_mode & 0o777) == 0o600
    assert V.unlock(path, interactive=False)[1] == "session"
    V.end_session(path)
    with pytest.raises(V.VaultLocked):
        V.unlock(path, interactive=False)

    sf = V.start_session(v, ttl=1)
    assert V.session_key(path) == v.key
    time.sleep(1.3)
    assert V.session_key(path) is None and not sf.exists()  # expiry also deletes the cached key

    V.start_session(v, ttl=600)
    v.put(V.Credential(name="x", value="some-secret-value", kind="none"))  # leaves a .bak under the old key
    v.change_passphrase("a completely new passphrase")
    assert V.session_key(path) is None  # re-keying invalidates sessions
    assert not path.with_name("vault.json.bak").exists()  # ...and drops the old-key backup
    with pytest.raises(V.BadPassphrase):
        V.Vault.open(path, PW)
    assert V.Vault.open(path, "a completely new passphrase").creds["x"].value == "some-secret-value"


def test_keychain_session_store_ttl_lock_and_rotation(kv, monkeypatch):
    class MemoryKeychain:
        def __init__(self):
            self.items = {}
            self.fail_delete = False

        def get_password(self, service, username):
            return self.items.get((service, username))

        def set_password(self, service, username, password):
            self.items[(service, username)] = password

        def delete_password(self, service, username):
            if self.fail_delete:
                raise RuntimeError("backend failure")
            del self.items[(service, username)]

    store = MemoryKeychain()
    monkeypatch.setenv("KEYVAULT_SESSION_BACKEND", "keychain")
    monkeypatch.setattr(V, "_native_keychain_backend", lambda: store)
    path = V.vault_path()
    v = V.Vault.create(path, PW, log_n=LOG_N)
    location = V.start_session(v, ttl=600)
    assert location == "native OS keychain"
    service, username = V._session_keychain_id(path)
    assert (service, username) in store.items
    assert not V.session_file(path).exists()  # derived key did not hit the filesystem
    assert V.session_key(path) == v.key
    assert V.unlock(path, interactive=False)[1] == "session"

    # Expiration invalidates the session even if the credential item still exists.
    payload = json.loads(store.items[(service, username)])
    payload["expires"] = time.time() - 1
    store.items[(service, username)] = json.dumps(payload)
    assert V.session_key(path) is None
    assert (service, username) not in store.items

    V.start_session(v, ttl=600)
    v.put(V.Credential(name="rotated", value="a-safe-test-secret", kind="none"))
    v.change_passphrase("a completely new passphrase")
    assert V.session_key(path) is None  # the vault salt changed, so the cached key is rejected

    V.start_session(V.Vault.open(path, "a completely new passphrase"), ttl=600)
    store.fail_delete = True
    with pytest.raises(V.VaultError, match="keychain delete failed"):
        V.end_session(path)
    assert (service, username) in store.items  # lock never claims success when the keychain refused deletion


def test_keychain_unavailable_never_falls_back_to_file(kv, monkeypatch):
    monkeypatch.setenv("KEYVAULT_SESSION_BACKEND", "keychain")
    path = V.vault_path()
    v = V.Vault.create(path, PW, log_n=LOG_N)

    def unavailable():
        raise V.VaultError("native OS keychain is unavailable")

    monkeypatch.setattr(V, "_native_keychain_backend", unavailable)
    with pytest.raises(V.VaultError, match="native OS keychain is unavailable"):
        V.start_session(v, ttl=600)
    assert not V.session_file(path).exists()


def test_session_backend_setting_is_validated(kv, monkeypatch):
    monkeypatch.setenv("KEYVAULT_SESSION_BACKEND", "auto-fallback")
    with pytest.raises(V.VaultError, match="KEYVAULT_SESSION_BACKEND must be"):
        V.session_backend_name()


def test_handle_reloads_rotation_and_honours_session(kv):
    path = V.vault_path()
    v = V.Vault.create(path, PW, log_n=LOG_N)
    v.put(V.Credential(name="a", value="first-secret-value", kind="none"))

    h = V.VaultHandle(path, V.Vault.open(path, PW), "env")
    assert h.current().creds["a"].value == "first-secret-value"
    w = V.Vault.open(path, PW)
    w.creds["a"].value = "second-secret-value"
    w.save()  # a rotation made by another process
    assert h.current().creds["a"].value == "second-secret-value"

    V.start_session(v, ttl=600)
    hs = V.VaultHandle(path, V.Vault.open_with_key(path, v.key), "session")
    assert hs.current().creds["a"].value == "second-secret-value"
    V.end_session(path)
    with pytest.raises(V.VaultLocked):
        hs.current()
    V.start_session(V.Vault.open(path, PW), ttl=600)
    assert hs.current().creds["a"].value == "second-secret-value"  # resumes after unlock


@pytest.mark.parametrize("kw", [
    dict(name="Bad Name", value="x" * 10, kind="none"),
    dict(name="a", value="", kind="none"),
    dict(name="a", value="x" * 10, kind="bearer"),  # no hosts
    dict(name="a", value="x" * 10, kind="bearer", hosts=["https://api.x.com"]),
    dict(name="a", value="x" * 10, kind="bearer", hosts=["api.x.com/path"]),
    dict(name="a", value="x" * 10, kind="bearer", hosts=["*x.com"]),
    dict(name="a", value="x\ny", kind="bearer", hosts=["a.com"]),  # header-injection shaped secret
    dict(name="a", value="x" * 10, kind="header", hosts=["a.com"]),  # header kind without header name
    dict(name="a", value="x" * 10, kind="basic", hosts=["a.com"]),  # basic without user:password
    dict(name="a", value="x" * 10, kind="bearer", hosts=["a.com"], methods=["TRACE"]),
    dict(name="a", value="x" * 10, kind="none", env_var="1BAD"),
])
def test_validation_rejects(kw):
    with pytest.raises(V.VaultError):
        V.Credential(**kw).validate()


def test_host_matching():
    m = V.host_matches
    assert m("api.github.com", "api.github.com")
    assert m("A.Example.COM.", "a.example.com")
    assert m("a.b.example.com", "*.example.com")
    assert not m("example.com", "*.example.com")
    assert not m("evilexample.com", "*.example.com")
    assert not m("api.github.com.evil.com", "api.github.com")


def test_agent_view_hides_private_fields():
    c = V.Credential(name="gh", value=SECRET, kind="bearer", hosts=["api.github.com"], provider="github",
                     env_var="GITHUB_TOKEN", notes="private note", tags=["dev"])
    c.validate()
    view = c.agent_view()
    assert set(view) == {"name", "provider", "hosts", "methods", "tags"}
    blob = json.dumps(view)
    assert SECRET not in blob and "GITHUB_TOKEN" not in blob and "private note" not in blob
    assert "value" not in c.public() and "private note" in json.dumps(c.public())


# --------------------------------------------------------------------------- proxy: injection + policy

def test_injection_all_kinds_and_redaction(server):
    srv, base = server
    basic_value = "alice:s3cr3t-passw0rd-xyz"
    cases = [
        (mk("bearer"), lambda s: s["headers"]["authorization"] == f"Bearer {SECRET}"),
        (mk("header", header_name="x-api-key"), lambda s: s["headers"]["x-api-key"] == SECRET),
        (mk("query", param_name="key"), lambda s: f"key={SECRET}" in s["path"]),
        (mk("basic", value=basic_value),
         lambda s: s["headers"]["authorization"] == "Basic " + base64.b64encode(basic_value.encode()).decode()),
    ]
    for cred, check in cases:
        r = go(cred, method="GET", url=f"{base}/x?a=1", params={"b": "2"})
        seen = srv.seen[-1]
        assert check(seen), cred.kind
        assert "a=1" in seen["path"] and "b=2" in seen["path"], cred.kind
        blob = json.dumps(r)
        assert cred.value not in blob, cred.kind
        assert base64.b64encode(cred.value.encode()).decode() not in blob, cred.kind
        assert r["status"] == 200 and r["redactions"] >= 1, cred.kind
        assert "x-secret-echo" not in r["headers"]  # not on the response-header allowlist


@pytest.mark.parametrize("url,why", [
    ("https://evil.example/x", "not allowed"),
    ("https://127.0.0.1.evil.example/", "not allowed"),
    ("http://127.0.0.1.evil.example/", "only https"),
    ("file:///etc/passwd", "only https"),
    ("ftp://127.0.0.1/x", "only https"),
    ("https://127.0.0.1@evil.example/x", "embedded credentials"),
    ("http://127.0.0.1:1@evil.example/", "embedded credentials"),
    ("https://user:pw@127.0.0.1/x", "embedded credentials"),  # host is allowed; only the userinfo check stops it
    ("http://evil.example\\@127.0.0.1/", "backslashes"),
    ("http://127.0.0.1/ x", "spaces"),
    ("", "only https"),
    ("https://", "no host"),
])
def test_denied_urls_never_reach_the_network(server, url, why):
    srv, base = server
    before = len(srv.seen)
    with pytest.raises(ProxyError) as ei:
        go(mk(), method="GET", url=url)
    assert why in str(ei.value)  # refused by policy, not by a network failure
    assert len(srv.seen) == before


def test_policy_rules(server):
    srv, base = server
    n = len(srv.seen)
    bearer = mk("bearer")
    with pytest.raises(ProxyError, match="not enabled"):
        go(bearer, method="POST", url=f"{base}/x")  # read-only by default
    with pytest.raises(ProxyError, match="env-only"):
        go(mk("none"), method="GET", url=f"{base}/x")
    for h in ({"Authorization": "Bearer attacker"}, {"authorization": "x"}, {"Host": "evil.example"}, {"Content-Length": "5"}):
        with pytest.raises(ProxyError, match="managed by keyvault"):
            go(bearer, method="GET", url=f"{base}/x", headers=h)
    with pytest.raises(ProxyError, match="managed by keyvault"):
        go(mk("header", header_name="X-API-Key"), method="GET", url=f"{base}/x", headers={"x-api-key": "mine"})
    with pytest.raises(ProxyError, match="reserved"):
        go(mk("query", param_name="key"), method="GET", url=f"{base}/x?key=1")
    with pytest.raises(ProxyError, match="reserved"):
        go(mk("query", param_name="key"), method="GET", url=f"{base}/x", params={"key": "1"})
    with pytest.raises(ProxyError, match="either json_body or body"):
        go(mk(methods=["POST"]), method="POST", url=f"{base}/x", json_body={}, body="x")
    assert len(srv.seen) == n  # every one of those was refused before anything was sent


def test_post_with_json_body_and_extra_headers(server):
    srv, base = server
    r = go(mk(methods=["GET", "POST"]), method="post", url=f"{base}/items", json_body={"a": [1, 2]}, headers={"X-Trace": "t1"})
    seen = srv.seen[-1]
    assert r["status"] == 200 and seen["method"] == "POST"
    assert json.loads(seen["body"]) == {"a": [1, 2]}
    assert seen["headers"]["content-type"].startswith("application/json")
    assert seen["headers"]["x-trace"] == "t1" and seen["headers"]["user-agent"].startswith("keyvault/")
    go(mk(methods=["POST"]), method="POST", url=f"{base}/raw", body="plain text")
    assert srv.seen[-1]["body"] == "plain text"


def test_redirect_not_followed(server, server2):
    srv, base = server
    srv2, base2 = server2
    srv.redirect_to = f"{base2}/steal"
    r = go(mk(), method="GET", url=f"{base}/redirect")
    assert r["status"] == 302 and r["headers"]["location"] == f"{base2}/steal"
    assert "redirect not followed" in r["note"]
    assert srv2.seen == []  # the second server never saw a request, let alone the credential


@pytest.mark.parametrize("at", [900, 960, 980, 990, 995, 1000, 1020, 1040, 1055])
def test_truncation_never_leaks_a_partial_secret(server, at):
    srv, base = server
    srv.straddle_at = at  # place the secret so it straddles the size cut at many offsets
    r = go(mk(), method="GET", url=f"{base}/straddle", max_bytes=1000)
    body = r["body"]
    assert r["truncated"] is True and len(body.encode()) <= 1000
    for k in range(4, len(SECRET) + 1):
        assert SECRET[:k] not in body, (at, k)


def test_truncation_after_earlier_redactions_shrank_the_text(server):
    srv, base = server
    srv.straddle_at = 548  # last secret starts at raw offset 1040, straddling the 1056-byte read window
    r = go(mk(), method="GET", url=f"{base}/many", max_bytes=1000)
    assert r["redactions"] >= 12 and r["truncated"] is True
    for k in range(4, len(SECRET) + 1):
        assert SECRET[:k] not in r["body"], k


def test_truncation_returns_the_full_budget(server):
    srv, base = server
    srv.straddle_at = 4000  # the secret lies far beyond the cut
    r = go(mk(), method="GET", url=f"{base}/straddle", max_bytes=1000)
    assert r["truncated"] is True and len(r["body"].encode()) == 1000


def test_binary_omitted_and_response_headers_filtered(server):
    srv, base = server
    r = go(mk(), method="GET", url=f"{base}/binary")
    assert r["body"] is None and "non-text" in r["note"]
    assert "x-secret-echo" not in r["headers"] and SECRET not in json.dumps(r)
    assert r["headers"]["link"].count("[REDACTED:local]") == 1
    small = go(mk(), method="GET", url=f"{base}/x")
    assert small["truncated"] is False


def test_audit_log_records_without_secrets(server, kv):
    srv, base = server
    go(mk("query", param_name="key"), method="GET", url=f"{base}/a", params={"q": "1"})
    with pytest.raises(ProxyError):
        go(mk(), method="GET", url="https://evil.example/")
    log = kv / "kv" / "audit.log"
    raw = log.read_text()
    assert SECRET not in raw
    events = [json.loads(line) for line in raw.splitlines()]
    ok = next(e for e in events if e["action"] == "http_request")
    assert ok["credential"] == "local" and ok["host"] == "127.0.0.1" and ok["status"] == 200
    assert ok["query_keys"] == ["q"]  # the credential's own query parameter is not logged
    denied = next(e for e in events if e["action"] == "http_denied")
    assert "evil.example" in denied["reason"]
    assert (log.stat().st_mode & 0o777) == 0o600


# --------------------------------------------------------------------------- CLI

def test_parse_dotenv():
    text = '''
# comment
OPENAI_API_KEY=sk-openai-aaaaaaaaaaaa
export GITHUB_TOKEN="ghp_bbbbbbbbbbbb" # trailing comment
EMPTY=
SPACED = ' quoted value with # hash '
NOT A VAR
STRIPE_KEY=sk_test_cccccc # inline comment
ESCAPED="line1\\nline2 \\"q\\""
1BAD=x
'''
    assert dict(parse_dotenv(text)) == {
        "OPENAI_API_KEY": "sk-openai-aaaaaaaaaaaa",
        "GITHUB_TOKEN": "ghp_bbbbbbbbbbbb",
        "SPACED": " quoted value with # hash ",
        "STRIPE_KEY": "sk_test_cccccc",
        "ESCAPED": 'line1\nline2 "q"',
    }


def test_cli_flow(kv):
    assert run_cli(kv, "init", "--kdf-log-n", str(LOG_N)).returncode == 0
    r = run_cli(kv, "add", "github", "--provider", "github", "--kind", "bearer", "--host", "api.github.com",
                "--env-var", "GITHUB_TOKEN", "--methods", "GET,POST", "--tag", "dev", "--note", "private note",
                "--value-stdin", input=SECRET + "\n")
    assert r.returncode == 0, r.stderr

    for args in (("list",), ("list", "--json"), ("show", "github")):
        r = run_cli(kv, *args)
        assert r.returncode == 0 and SECRET not in r.stdout + r.stderr, args
    assert "api.github.com" in run_cli(kv, "list").stdout
    assert run_cli(kv, "get", "github").stdout.strip() == SECRET
    assert run_cli(kv, "add", "bad", "--value", SECRET).returncode != 0  # no way to pass a secret as an argument

    r = run_cli(kv, "run", "github", "--", sys.executable, "-c",
                "import os; print(os.environ['GITHUB_TOKEN'], 'KEYVAULT_PASSPHRASE' in os.environ)")
    assert r.stdout.split() == [SECRET, "False"], r.stderr  # injected, and the master passphrase is not passed on
    r = run_cli(kv, "run", "-e", "FOO=github", "--", sys.executable, "-c", "import os; print(os.environ['FOO'])")
    assert r.stdout.strip() == SECRET
    r = run_cli(kv, "run", "nosuch", "--", "true")
    assert r.returncode != 0 and "no credential named 'nosuch'" in r.stderr
    assert run_cli(kv, "run", "github", "--", "definitely-not-a-command-xyz").returncode == 127

    r = run_cli(kv, "list", passphrase="not the passphrase")
    assert r.returncode != 0 and "wrong passphrase" in r.stderr

    assert run_cli(kv, "edit", "github", "--methods", "GET").returncode == 0  # settings change keeps the secret
    assert run_cli(kv, "get", "github").stdout.strip() == SECRET
    new = "sk-live-rotated-0000000000000000000000"
    assert run_cli(kv, "edit", "github", "--rotate", "--value-stdin", input=new).returncode == 0
    assert run_cli(kv, "get", "github").stdout.strip() == new

    out = run_cli(kv, "audit", "-n", "50").stdout
    assert '"action": "run"' in out and '"action": "get"' in out and '"action": "rotate"' in out
    assert SECRET not in out and new not in out

    assert run_cli(kv, "rm", "github").returncode != 0  # no TTY and no --yes: refuses
    assert run_cli(kv, "rm", "github", "--yes").returncode == 0
    assert "github" not in run_cli(kv, "list").stdout


def test_cli_import_env(kv):
    run_cli(kv, "init", "--kdf-log-n", str(LOG_N))
    run_cli(kv, "add", "github_token", "--kind", "bearer", "--host", "api.github.com", "--env-var", "GITHUB_TOKEN",
            "--value-stdin", input="old-github-token-value")
    envfile = kv / "sample.env"
    envfile.write_text(
        "# comment\n"
        "OPENAI_API_KEY=sk-openai-aaaaaaaaaaaa\n"
        'export GITHUB_TOKEN="ghp_bbbbbbbbbbbb" # trailing comment\n'
        "EMPTY=\n"
        "STRIPE_KEY=sk_test_cccccc # inline comment\n"
    )
    r = run_cli(kv, "import-env", str(envfile), "--dry-run", passphrase=None)  # needs no unlock
    assert r.returncode == 0 and "OPENAI_API_KEY -> openai_api_key" in r.stdout
    assert "sk-openai" not in r.stdout + r.stderr

    r = run_cli(kv, "import-env", str(envfile))
    assert r.returncode == 0, r.stderr
    assert "skip    github_token" in r.stdout and "add     openai_api_key" in r.stdout
    assert "sk-openai" not in r.stdout + r.stderr and "ghp_bbbb" not in r.stdout + r.stderr
    assert run_cli(kv, "get", "github_token").stdout.strip() == "old-github-token-value"  # not overwritten
    r = run_cli(kv, "run", "openai_api_key", "stripe_key", "--", sys.executable, "-c",
                "import os; print(os.environ['OPENAI_API_KEY'], os.environ['STRIPE_KEY'])")
    assert r.stdout.split() == ["sk-openai-aaaaaaaaaaaa", "sk_test_cccccc"], r.stderr

    r = run_cli(kv, "import-env", str(envfile), "--overwrite")
    assert "update  github_token" in r.stdout
    assert run_cli(kv, "get", "github_token").stdout.strip() == "ghp_bbbbbbbbbbbb"
    shown = json.loads(run_cli(kv, "show", "github_token").stdout)
    assert shown["hosts"] == ["api.github.com"] and shown["kind"] == "bearer"  # settings survive a value refresh


def test_cli_unlock_and_lock(kv):
    run_cli(kv, "init", "--kdf-log-n", str(LOG_N))
    run_cli(kv, "add", "x", "--value-stdin", input="some-secret-value-123")
    assert run_cli(kv, "list", passphrase=None).returncode != 0  # locked, and there is no TTY to prompt on
    assert run_cli(kv, "unlock", "--ttl", "5m").returncode == 0
    r = run_cli(kv, "list", passphrase=None)
    assert r.returncode == 0 and "x" in r.stdout
    assert run_cli(kv, "lock", passphrase=None).returncode == 0
    r = run_cli(kv, "list", passphrase=None)
    assert r.returncode != 0 and "locked" in r.stderr


def test_snippets(kv):
    r = run_cli(kv, "snippet", "serve", "--allow", "github", passphrase=None)
    entry = json.loads(r.stdout)["mcpServers"]["keyvault"]
    assert os.path.samefile(entry["command"], sys.executable)  # same interpreter, however the path is spelled
    assert entry["args"] == ["-m", "keyvault", "serve", "--allow", "github"]
    assert entry["env"] == {
        "KEYVAULT_HOME": str(kv / "kv"),
        "KEYVAULT_SESSION_BACKEND": "file",
    }

    r = run_cli(kv, "snippet", "run", "github", "-e", "ALT=other", "--", "npx", "-y", "@modelcontextprotocol/server-github",
                passphrase=None)
    entry = json.loads(r.stdout)["mcpServers"]["github"]
    assert entry["args"] == ["-m", "keyvault", "run", "github", "-e", "ALT=other", "--",
                             "npx", "-y", "@modelcontextprotocol/server-github"]


def test_serve_refuses_when_locked_or_misconfigured(kv):
    run_cli(kv, "init", "--kdf-log-n", str(LOG_N))
    run_cli(kv, "add", "x", "--kind", "bearer", "--host", "api.example.com", "--value-stdin", input="some-secret-value")
    r = run_cli(kv, "serve", passphrase=None)
    assert r.returncode != 0 and "locked" in r.stderr
    r = run_cli(kv, "serve", "--allow", "x,nope")
    assert r.returncode != 0 and "nope" in r.stderr


# --------------------------------------------------------------------------- MCP end to end (stdio)

def _text(res):
    return "".join(getattr(c, "text", "") for c in res.content)


def _listing(res):
    sc = getattr(res, "structured_content", None)
    if sc and "result" in sc:
        return sc["result"]
    return [json.loads(c.text) for c in res.content if getattr(c, "text", None)]


def test_mcp_end_to_end(server, kv, tmp_path):
    from mcp import ClientSession, StdioServerParameters, stdio_client

    srv, base = server
    assert run_cli(kv, "init", "--kdf-log-n", str(LOG_N)).returncode == 0
    adds = [
        ("local", ["--provider", "demo", "--kind", "bearer", "--host", "127.0.0.1", "--methods", "GET,POST",
                   "--env-var", "LOCAL_TOKEN", "--tag", "t1", "--note", "NOTE-SHOULD-NOT-LEAK"], SECRET),
        ("other", ["--kind", "bearer", "--host", "other.example"], OTHER),
        ("envonly", ["--env-var", "DB_URL"], "postgres://user:pw@host/db"),
    ]
    for name, flags, value in adds:
        r = run_cli(kv, "add", name, *flags, "--value-stdin", input=value)
        assert r.returncode == 0, r.stderr
    assert run_cli(kv, "unlock", "--ttl", "5m").returncode == 0

    env = child_env(kv)  # no passphrase: the server has to unlock through the session
    errfile = tmp_path / "server.err"

    async def scenario():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "keyvault", "serve", "--allow", "local,envonly"], env=env)
        out = {}
        with open(errfile, "w+") as errf:
            async with stdio_client(params, errlog=errf) as (rd, wr):
                async with ClientSession(rd, wr) as s:
                    await s.initialize()
                    call = s.call_tool
                    out["tools"] = await s.list_tools()
                    out["list"] = await call("list_credentials", {})
                    out["get"] = await call("http_request", {
                        "credential": "local", "method": "GET", "url": f"{base}/hello", "params": {"q": "1"}})
                    out["post"] = await call("http_request", {
                        "credential": "local", "method": "POST", "url": f"{base}/p", "json_body": {"a": 1}})
                    out["oos"] = await call("http_request", {
                        "credential": "other", "method": "GET", "url": "https://other.example/"})
                    out["envonly"] = await call("http_request", {
                        "credential": "envonly", "method": "GET", "url": f"{base}/"})
                    out["wrong_host"] = await call("http_request", {
                        "credential": "local", "method": "GET", "url": "https://evil.example/"})
                    out["put"] = await call("http_request", {
                        "credential": "local", "method": "PUT", "url": f"{base}/p"})
                    out["seen_before_lock"] = len(srv.seen)
                    out["lock_rc"] = run_cli(kv, "lock", passphrase=None).returncode
                    out["locked"] = await call("http_request", {
                        "credential": "local", "method": "GET", "url": f"{base}/hello"})
                    out["locked_list"] = await call("list_credentials", {})
        return out

    out = asyncio.run(scenario())

    assert {t.name for t in out["tools"].tools} == {"list_credentials", "http_request"}  # no tool returns a secret

    listing = _listing(out["list"])  # only in-scope HTTP credentials; envonly and other are invisible
    assert [c["name"] for c in listing] == ["local"]
    assert set(listing[0]) == {"name", "provider", "hosts", "methods", "tags"}

    assert not out["get"].is_error and json.loads(_text(out["get"]))["status"] == 200
    assert not out["post"].is_error and json.loads(_text(out["post"]))["status"] == 200
    first, second = srv.seen[0], srv.seen[1]
    assert first["headers"]["authorization"] == f"Bearer {SECRET}" and "q=1" in first["path"]
    assert second["method"] == "POST" and json.loads(second["body"]) == {"a": 1}

    for key, fragment in (("oos", "unknown credential"), ("envonly", "unknown credential"),
                          ("wrong_host", "not allowed"), ("put", "not enabled")):
        assert out[key].is_error, key
        assert fragment in _text(out[key]), (key, _text(out[key]))
    assert out["seen_before_lock"] == 2  # none of the refused calls reached the network

    assert out["lock_rc"] == 0  # `keyvault lock` cuts off a server that was started from a session
    for key in ("locked", "locked_list"):
        assert out[key].is_error and "locked" in _text(out[key]), key
    assert len(srv.seen) == 2

    blob = "".join(v.model_dump_json() for v in out.values() if hasattr(v, "model_dump_json"))
    blob += errfile.read_text() + (kv / "kv" / "audit.log").read_text()
    for needle in (SECRET, OTHER, "NOTE-SHOULD-NOT-LEAK", "LOCAL_TOKEN", "DB_URL", "postgres://"):
        assert needle not in blob, needle


def test_run_wraps_a_third_party_stdio_mcp_server(kv, tmp_path):
    """`keyvault run` in front of an unrelated MCP server: token arrives in its env, stdio stays clean."""
    import hashlib

    from mcp import ClientSession, StdioServerParameters, stdio_client

    server_py = tmp_path / "thirdparty_server.py"
    server_py.write_text(
        "import hashlib, os\n"
        "from mcp.server.mcpserver import MCPServer\n"
        "mcp = MCPServer('thirdparty')\n"
        "@mcp.tool()\n"
        "def whoami() -> dict:\n"
        "    '''Report a fingerprint of the token this server was started with (never the token).'''\n"
        "    t = os.environ.get('MY_SERVICE_TOKEN', '')\n"
        "    return {'sha8': hashlib.sha256(t.encode()).hexdigest()[:8], 'len': len(t),\n"
        "            'passphrase_in_env': 'KEYVAULT_PASSPHRASE' in os.environ}\n"
        "mcp.run()\n"
    )
    assert run_cli(kv, "init", "--kdf-log-n", str(LOG_N)).returncode == 0
    token = "svc-token-5d41402abc4b2a76b9719d91"
    assert run_cli(kv, "add", "svc", "--env-var", "MY_SERVICE_TOKEN", "--value-stdin", input=token).returncode == 0
    assert run_cli(kv, "unlock", "--ttl", "5m").returncode == 0

    async def scenario():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "keyvault", "run", "svc", "--", sys.executable, str(server_py)],
            env=child_env(kv),  # no passphrase in the client's config or env: session only
        )
        with open(tmp_path / "wrapped.err", "w+") as errf:
            async with stdio_client(params, errlog=errf) as (rd, wr):
                async with ClientSession(rd, wr) as s:
                    await s.initialize()
                    return await s.call_tool("whoami", {})

    res = asyncio.run(scenario())
    info = json.loads(_text(res))
    assert info == {"sha8": hashlib.sha256(token.encode()).hexdigest()[:8], "len": len(token), "passphrase_in_env": False}
    assert token not in res.model_dump_json() + (tmp_path / "wrapped.err").read_text()
