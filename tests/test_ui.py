import http.client
import json
import threading
from urllib.parse import urlsplit

import pytest

from keyvault import vault as V
from keyvault.ui import KeyvaultUIServer

PASSWORD = "ui test passphrase longer"
SECRET = "ui-secret-value-DO-NOT-RETURN-123456"


@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYVAULT_HOME", str(tmp_path / "keyvault"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("KEYVAULT_SESSION_BACKEND", "file")
    monkeypatch.delenv("KEYVAULT_PASSPHRASE", raising=False)
    server = KeyvaultUIServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def request(server, path, data=None, *, origin=None, token=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Origin"] = origin if origin is not None else f"http://127.0.0.1:{server.server_port}"
        headers["X-Keyvault-UI"] = server.csrf_token if token is None else token
    if host:
        headers["Host"] = host
    body = json.dumps(data).encode() if data is not None else None
    conn.request("POST" if data is not None else "GET", path, body=body, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    result = json.loads(raw) if response.getheader("Content-Type", "").startswith("application/json") else raw.decode()
    status = response.status
    response_headers = dict(response.getheaders())
    conn.close()
    return status, result, response_headers


def post(server, path, data, **kwargs):
    return request(server, path, data, **kwargs)


def test_ui_is_loopback_only_and_defends_host_origin_and_csrf(ui):
    status, html, headers = request(ui, "/")
    assert status == 200
    assert "__KEYVAULT_CSRF_TOKEN__" not in html
    assert ui.csrf_token in html
    assert headers["Content-Security-Policy"].find("frame-ancestors 'none'") >= 0
    assert headers["Cache-Control"] == "no-store"
    assert 'src="https://' not in html and 'href="https://' not in html

    status, data, _ = post(ui, "/api/init", {"passphrase": PASSWORD, "confirm": PASSWORD},
                           origin="https://attacker.example")
    assert status == 403 and data["error"] == "Origin rejected."

    status, data, _ = post(ui, "/api/init", {"passphrase": PASSWORD, "confirm": PASSWORD}, token="wrong")
    assert status == 403 and "token rejected" in data["error"].lower()

    status, data, _ = request(ui, "/", host="attacker.example")
    assert status == 403 and "Host header rejected" in data["error"]

    with pytest.raises(ValueError, match="only bind to 127.0.0.1"):
        KeyvaultUIServer(("0.0.0.0", 0))


def test_ui_create_manage_rotate_delete_lock_and_sanitized_audit(ui, tmp_path):
    status, data, _ = post(ui, "/api/init", {
        "passphrase": PASSWORD, "confirm": PASSWORD, "ttl_seconds": 3600
    })
    assert status == 201 and data["ok"]
    assert SECRET not in json.dumps(data)

    status, data, _ = request(ui, "/api/status")
    assert status == 200 and data["initialized"] and data["unlocked"]
    assert data["credential_count"] == 0
    assert data["session_backend"] == "file"

    credential = {
        "name": "github",
        "provider": "GitHub",
        "kind": "bearer",
        "secret": SECRET,
        "hosts": ["api.github.com"],
        "methods": ["GET", "POST"],
        "env_var": "GITHUB_TOKEN",
        "tags": ["development", "automation"],
        "notes": "owner-private note",
        "header_name": "",
        "param_name": "",
    }
    status, data, _ = post(ui, "/api/credentials/save", credential)
    assert status == 200 and data["ok"]
    assert SECRET not in json.dumps(data)

    status, data, _ = request(ui, "/api/credentials")
    assert status == 200 and len(data["credentials"]) == 1
    exposed = json.dumps(data)
    assert SECRET not in exposed
    assert "owner-private note" in exposed and "GITHUB_TOKEN" in exposed
    assert data["credentials"][0]["methods"] == ["GET", "POST"]

    # A blank secret during edits preserves the current secret.
    edited = dict(credential, secret="", provider="GitHub Actions")
    status, data, _ = post(ui, "/api/credentials/save", edited)
    assert status == 200
    vault = V.Vault.open(V.vault_path(), PASSWORD)
    assert vault.creds["github"].value == SECRET
    assert vault.creds["github"].provider == "GitHub Actions"

    rotated = dict(edited, secret="rotated-secret-value-456789abcdef")
    status, data, _ = post(ui, "/api/credentials/save", rotated)
    assert status == 200 and "rotated-secret-value-456789abcdef" not in json.dumps(data)
    vault = V.Vault.open(V.vault_path(), PASSWORD)
    assert vault.creds["github"].value == "rotated-secret-value-456789abcdef"

    status, data, _ = post(ui, "/api/snippet", {"allow": ["github"]})
    assert status == 200 and data["credential_count"] == 1
    snippet = json.loads(data["snippet"])
    entry = snippet["mcpServers"]["keyvault"]
    assert entry["args"] == ["-m", "keyvault", "serve", "--allow", "github"]
    assert SECRET not in data["snippet"] and "rotated-secret-value-456789abcdef" not in data["snippet"]
    status, data, _ = post(ui, "/api/snippet", {"allow": []})
    assert status == 400 and "select at least one" in data["error"].lower()

    status, data, _ = request(ui, "/api/audit")
    audit_text = json.dumps(data)
    assert status == 200 and "credential_added" in audit_text and "credential_saved" in audit_text
    assert "snippet_generated" in audit_text
    assert SECRET not in audit_text
    assert "rotated-secret-value-456789abcdef" not in audit_text

    status, data, _ = post(ui, "/api/credentials/delete", {"name": "github"})
    assert status == 200 and "github" in data["message"]
    assert V.Vault.open(V.vault_path(), PASSWORD).creds == {}

    status, data, _ = post(ui, "/api/lock", {})
    assert status == 200 and data["ok"]
    status, data, _ = request(ui, "/api/status")
    assert status == 200 and not data["unlocked"]
    status, data, _ = request(ui, "/api/credentials")
    assert status == 423 and "locked" in data["error"].lower()


def test_ui_rejects_invalid_policy_and_does_not_partially_initialize(ui):
    status, data, _ = post(ui, "/api/init", {
        "passphrase": PASSWORD, "confirm": PASSWORD, "ttl_seconds": 5
    })
    assert status == 400
    assert not V.vault_path().exists()  # validate TTL before creating any persistent vault

    status, data, _ = post(ui, "/api/init", {
        "passphrase": PASSWORD, "confirm": PASSWORD, "ttl_seconds": 3600
    })
    assert status == 201

    status, data, _ = post(ui, "/api/credentials/save", {
        "name": "github", "provider": "GitHub", "kind": "bearer", "secret": SECRET,
        "hosts": [], "methods": ["GET"], "header_name": "", "param_name": "", "env_var": "", "tags": [], "notes": ""
    })
    assert status == 400 and "host" in data["error"].lower()
    vault = V.Vault.open(V.vault_path(), PASSWORD)
    assert not vault.creds


def test_ui_unlock_attempt_throttle(ui):
    for _ in range(5):
        ui.record_unlock_failure()
    assert ui.unlock_rate_limited()
    ui.clear_unlock_failures()
    assert not ui.unlock_rate_limited()
